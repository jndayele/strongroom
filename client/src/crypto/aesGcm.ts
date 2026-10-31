import {
  type DataAadParams,
  encodeAad,
} from './aad.ts';
import {
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BITS,
   type DecodedEnvelope,
  ENVELOPE_OVERHEAD_BYTES,
  ENVELOPE_VERSION_V1,
  decodeEnvelope,
  encodeEnvelope,
} from './envelope.ts';
import { CryptoArgumentError, DecryptionError } from './errors.ts';
import { getWebCrypto, toArrayBuffer, wipeBuffers } from './memory.ts';
import {
  PADDING_BUCKET_BYTES,
  maxPaddedBytesForOverhead,
  padToBucket,
  unpadFromBucket,
} from './padding.ts';
import { secureRandom } from './random.ts';

/**
 * AES-256 key length in bytes (256 bits = 32 bytes).
 */
export const AES_256_KEY_BYTES = 32 as const;

/**
 * AES-256 key length in bits.
 */
export const AES_256_KEY_BITS = 256 as const;

/**
 * Maximum valid encrypted envelope length in bytes (for a 1 MiB plaintext).
 */
export const MAX_ENCRYPTED_ENVELOPE_BYTES =
  maxPaddedBytesForOverhead(ENVELOPE_OVERHEAD_BYTES) + ENVELOPE_OVERHEAD_BYTES;

const DATA_USAGE_SET: ReadonlySet<string> = new Set(['encrypt', 'decrypt']);
const WRAPPING_USAGE_SET: ReadonlySet<string> = new Set(['wrapKey', 'unwrapKey']);

/**
 * Validates that `usages` is a non-empty array of allowed AES-GCM usages and
 * never mixes leaf data usages (`encrypt`, `decrypt`) with key-wrapping usages
 * (`wrapKey`, `unwrapKey`).
 */
export function assertValidKeyUsages(
  usages: ReadonlyArray<KeyUsage>,
  expectedGroup?: 'data' | 'wrapping',
): void {
  if (!Array.isArray(usages) || usages.length === 0) {
    throw new CryptoArgumentError();
  }
  let hasDataUsage = false;
  let hasWrappingUsage = false;

  for (const usage of usages) {
    if (typeof usage !== 'string') {
      throw new CryptoArgumentError();
    }
    if (DATA_USAGE_SET.has(usage)) {
      hasDataUsage = true;
    } else if (WRAPPING_USAGE_SET.has(usage)) {
      hasWrappingUsage = true;
    } else {
      throw new CryptoArgumentError();
    }
  }

  if (hasDataUsage && hasWrappingUsage) {
    throw new CryptoArgumentError();
  }
  if (expectedGroup === 'data' && !hasDataUsage) {
    throw new CryptoArgumentError();
  }
  if (expectedGroup === 'wrapping' && !hasWrappingUsage) {
    throw new CryptoArgumentError();
  }
}

export function isAes256GcmKey(key: unknown): key is CryptoKey {
  if (
    typeof globalThis.CryptoKey === 'function' &&
    !(key instanceof globalThis.CryptoKey)
  ) {
    return false;
  }
  if (
    typeof key !== 'object' ||
    key === null ||
    !('algorithm' in key) ||
    typeof (key as { readonly algorithm: unknown }).algorithm !== 'object' ||
    (key as { readonly algorithm: unknown }).algorithm === null
  ) {
    return false;
  }
  const cryptoKey = key as CryptoKey;
  const alg = cryptoKey.algorithm as AesKeyAlgorithm | undefined;
  return (
    cryptoKey.type === 'secret' &&
    alg !== undefined &&
    alg !== null &&
    alg.name === 'AES-GCM' &&
    alg.length === AES_256_KEY_BITS
  );
}

export function isAes256GcmDataKey(
  key: unknown,
  requiredUsage: 'encrypt' | 'decrypt',
): key is CryptoKey {
  if (!isAes256GcmKey(key) || key.extractable || !Array.isArray(key.usages)) {
    return false;
  }
  if (
    key.usages.length === 0 ||
    !key.usages.includes(requiredUsage) ||
    key.usages.some((u) => !DATA_USAGE_SET.has(u))
  ) {
    return false;
  }
  return true;
}

export function isAes256GcmWrappingKey(
  key: unknown,
  requiredUsage?: 'wrapKey' | 'unwrapKey',
): key is CryptoKey {
  if (!isAes256GcmKey(key) || key.extractable || !Array.isArray(key.usages)) {
    return false;
  }
  if (
    key.usages.length === 0 ||
    (requiredUsage !== undefined && !key.usages.includes(requiredUsage)) ||
    key.usages.some((u) => !WRAPPING_USAGE_SET.has(u))
  ) {
    return false;
  }
  return true;
}

/**
 * Generates a random non-extractable 256-bit AES-GCM CryptoKey (`extractable = false`).
 * Rejects any usages array that mixes data (`encrypt`, `decrypt`) and wrapping
 * (`wrapKey`, `unwrapKey`) usages.
 */
export async function generateAesGcmKey(
  usages: ReadonlyArray<KeyUsage> = ['encrypt', 'decrypt'],
): Promise<CryptoKey> {
  assertValidKeyUsages(usages);
  const webCrypto = getWebCrypto();
  return await webCrypto.subtle.generateKey(
    { name: 'AES-GCM', length: AES_256_KEY_BITS },
    false,
    [...usages],
  );
}

/**
 * Imports 32 raw bytes as a non-extractable AES-256-GCM CryptoKey (`extractable = false`).
 * Rejects any usages array that mixes data (`encrypt`, `decrypt`) and wrapping
 * (`wrapKey`, `unwrapKey`) usages.
 * Wipes the temporary `ArrayBuffer` copy of `rawKey` in `finally`.
 */
export async function importAesGcmKey(
  rawKey: Uint8Array,
  usages: ReadonlyArray<KeyUsage> = ['encrypt', 'decrypt'],
): Promise<CryptoKey> {
  if (!(rawKey instanceof Uint8Array) || rawKey.byteLength !== AES_256_KEY_BYTES) {
    throw new CryptoArgumentError();
  }
  assertValidKeyUsages(usages);

  let keyBuffer: ArrayBuffer | undefined;
  try {
    const webCrypto = getWebCrypto();
    keyBuffer = toArrayBuffer(rawKey);
    return await webCrypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: AES_256_KEY_BITS },
      false,
      [...usages],
    );
  } finally {
    wipeBuffers(keyBuffer);
  }
}

const ALLOWED_DATA_PURPOSES: ReadonlySet<string> = new Set([
  'item-meta',
  'item-secret',
]);

/**
 * Encrypts `plaintext` with AES-256-GCM using a fresh 96-bit random nonce,
 * required structured AAD, and 256-byte bucket padding, returning a versioned
 * binary envelope `[version (1B) || nonce (12B) || ciphertext + tag]` whose
 * total length is an exact multiple of 256 bytes.
 */
export async function encrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: DataAadParams,
): Promise<Uint8Array> {
  if (
    !aad ||
    typeof aad !== 'object' ||
    !ALLOWED_DATA_PURPOSES.has(aad.purpose)
  ) {
    throw new CryptoArgumentError();
  }
  if (!isAes256GcmDataKey(key, 'encrypt') || !(plaintext instanceof Uint8Array)) {
    throw new CryptoArgumentError();
  }

  let aadBytes: Uint8Array | undefined;
  let paddedPlaintext: Uint8Array | undefined;
  let paddedBuffer: ArrayBuffer | undefined;
  let nonce: Uint8Array | undefined;
  let nonceBuffer: ArrayBuffer | undefined;
  let aadBuffer: ArrayBuffer | undefined;

  try {
    aadBytes = encodeAad(aad);
    const webCrypto = getWebCrypto();

    paddedPlaintext = padToBucket(plaintext, ENVELOPE_OVERHEAD_BYTES);
    paddedBuffer = toArrayBuffer(paddedPlaintext);
    nonce = secureRandom(AES_GCM_NONCE_BYTES);
    nonceBuffer = toArrayBuffer(nonce);
    aadBuffer = toArrayBuffer(aadBytes);

    const ciphertextBuffer = await webCrypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonceBuffer,
        additionalData: aadBuffer,
        tagLength: AES_GCM_TAG_BITS,
      },
      key,
      paddedBuffer,
    );

    const ciphertextWithTag = new Uint8Array(ciphertextBuffer);
    return encodeEnvelope(nonce, ciphertextWithTag, ENVELOPE_VERSION_V1);
  } finally {
    wipeBuffers(
      paddedPlaintext,
      paddedBuffer,
      nonce,
      nonceBuffer,
      aadBuffer,
      aadBytes,
    );
  }
}

/**
 * Decrypts a versioned AES-256-GCM binary envelope with required structured AAD
 * and removes 256-byte bucket padding.
 *
 * Any failure (wrong key, tampered version/nonce/ciphertext/tag/AAD, invalid
 * or oversize padding, or malformed inputs) throws the single generic
 * `DecryptionError`.
 */
export async function decrypt(
  key: CryptoKey,
  envelope: Uint8Array,
  aad: DataAadParams,
): Promise<Uint8Array> {
  if (
    !aad ||
    typeof aad !== 'object' ||
    !ALLOWED_DATA_PURPOSES.has(aad.purpose)
  ) {
    throw new CryptoArgumentError();
  }

  let aadBytes: Uint8Array | undefined;
  let decoded: DecodedEnvelope | undefined;
  let nonceBuffer: ArrayBuffer | undefined;
  let aadBuffer: ArrayBuffer | undefined;
  let ciphertextBuffer: ArrayBuffer | undefined;
  let decryptedBuffer: ArrayBuffer | undefined;
  let paddedPlaintext: Uint8Array | undefined;

  try {
    if (
      !isAes256GcmDataKey(key, 'decrypt') ||
      !(envelope instanceof Uint8Array) ||
      envelope.byteLength === 0 ||
      envelope.byteLength > MAX_ENCRYPTED_ENVELOPE_BYTES ||
      envelope.byteLength % PADDING_BUCKET_BYTES !== 0
    ) {
      throw new DecryptionError();
    }

    aadBytes = encodeAad(aad);
    decoded = decodeEnvelope(envelope);
    const webCrypto = getWebCrypto();

    nonceBuffer = toArrayBuffer(decoded.nonce);
    aadBuffer = toArrayBuffer(aadBytes);
    ciphertextBuffer = toArrayBuffer(decoded.ciphertextWithTag);

    decryptedBuffer = await webCrypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonceBuffer,
        additionalData: aadBuffer,
        tagLength: AES_GCM_TAG_BITS,
      },
      key,
      ciphertextBuffer,
    );

    paddedPlaintext = new Uint8Array(decryptedBuffer);
    return unpadFromBucket(paddedPlaintext, ENVELOPE_OVERHEAD_BYTES);
  } catch {
    throw new DecryptionError();
  } finally {
    wipeBuffers(
      decoded?.nonce,
      decoded?.ciphertextWithTag,
      nonceBuffer,
      aadBuffer,
      ciphertextBuffer,
      decryptedBuffer,
      paddedPlaintext,
      aadBytes,
    );
  }
}
