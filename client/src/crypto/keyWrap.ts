import {
  type KeyWrapAadParams,
  type VaultKeyMasterAadParams,
  type VaultKeyWrapAadParams,
  encodeAad,
  toBoundedNonEmptyBytes,
} from './aad.ts';
import {
  AES_256_KEY_BITS,
  AES_256_KEY_BYTES,
  assertValidKeyUsages,
  importAesGcmKey,
  isAes256GcmWrappingKey,
} from './aesGcm.ts';
import {
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BITS,
  AES_GCM_TAG_BYTES,
  type DecodedEnvelope,
  ENVELOPE_OVERHEAD_BYTES,
  ENVELOPE_VERSION_V1,
  decodeEnvelope,
  encodeEnvelope,
} from './envelope.ts';
import { CryptoArgumentError, DecryptionError } from './errors.ts';
import {
  constantTimeEqual,
  getWebCrypto,
  toArrayBuffer,
  wipeBuffers,
} from './memory.ts';
import { secureRandom } from './random.ts';

/**
 * Expected total envelope size for a wrapped 256-bit key:
 * 1 byte version + 12 bytes nonce + 32 bytes key + 16 bytes GCM tag = 61 bytes.
 */
export const WRAPPED_KEY_ENVELOPE_BYTES =
  ENVELOPE_OVERHEAD_BYTES + AES_256_KEY_BYTES;

const WRAPPED_KEY_CIPHERTEXT_BYTES = AES_256_KEY_BYTES + AES_GCM_TAG_BYTES;

const VAULT_KEY_PURPOSES: ReadonlySet<string> = new Set([
  'vault-key-km',
  'vault-key-ks-master',
  'vault-key-ks-prf',
]);

const CREATE_VAULT_KEY_PURPOSES: ReadonlySet<string> = new Set([
  'vault-key-km',
  'vault-key-ks-master',
]);

const ALLOWED_WRAP_PURPOSES: ReadonlySet<string> = new Set([
  'vault-key-km',
  'vault-key-ks-master',
  'vault-key-ks-prf',
  'item-key-m',
  'item-key-s',
]);

/**
 * Generates a fresh 256-bit vault key (`K_m` or `K_s`), wraps it under
 * `wrappingKey` with AES-256-GCM + AAD, and returns a **non-extractable**
 * in-memory `CryptoKey` (`['wrapKey', 'unwrapKey']`) alongside the versioned
 * `wrappedKey` envelope.
 *
 * Raw key byte lifecycle:
 * 1. `rawKey` (32-byte `Uint8Array`) is allocated inside `try` via `secureRandom(32)`.
 * 2. `wrapKey` imports a short-lived function-local key (and wipes its
 *    internal `keyBuffer` in `wrapKey`'s `finally` block).
 * 3. `importAesGcmKey(rawKey, usages)` imports the non-extractable
 *    in-memory `CryptoKey` (and wipes its internal `keyBuffer` in `finally`).
 * 4. `createAndWrapVaultKey`'s `finally` block unconditionally zeroes `rawKey`
 *    on both success and any error path.
 */
export async function createAndWrapVaultKey(
  wrappingKey: CryptoKey,
  aad: VaultKeyMasterAadParams,
  usages: ReadonlyArray<KeyUsage> = ['wrapKey', 'unwrapKey'],
): Promise<{ readonly key: CryptoKey; readonly wrappedKey: Uint8Array }> {
  if (
    !aad ||
    typeof aad !== 'object' ||
    !CREATE_VAULT_KEY_PURPOSES.has(aad.purpose)
  ) {
    throw new CryptoArgumentError();
  }
  if (!isAes256GcmWrappingKey(wrappingKey, 'wrapKey')) {
    throw new CryptoArgumentError();
  }
  assertValidKeyUsages(usages, 'wrapping');

  let rawKey: Uint8Array | undefined;
  try {
    rawKey = secureRandom(AES_256_KEY_BYTES);
    const wrappedKey = await wrapKey(wrappingKey, rawKey, aad);
    const key = await importAesGcmKey(rawKey, usages);
    return { key, wrappedKey };
  } finally {
    wipeBuffers(rawKey);
  }
}

/**
 * Wraps a 32-byte raw vault or item key (`Uint8Array`) under `wrappingKey`
 * using WebCrypto `subtle.wrapKey('raw', ...)` with AES-256-GCM, a fresh
 * 96-bit random nonce, and required structured AAD, returning a versioned
 * binary envelope.
 *
 * The short-lived extractable `CryptoKey` needed by `subtle.wrapKey` is
 * strictly function-local and released in `finally`.
 */
export async function wrapKey(
  wrappingKey: CryptoKey,
  keyToWrap: Uint8Array,
  aad: KeyWrapAadParams,
): Promise<Uint8Array> {
  if (
    !aad ||
    typeof aad !== 'object' ||
    !ALLOWED_WRAP_PURPOSES.has(aad.purpose)
  ) {
    throw new CryptoArgumentError();
  }
  if (
    !isAes256GcmWrappingKey(wrappingKey, 'wrapKey') ||
    !(keyToWrap instanceof Uint8Array) ||
    keyToWrap.byteLength !== AES_256_KEY_BYTES
  ) {
    throw new CryptoArgumentError();
  }

  let aadBytes: Uint8Array | undefined;
  let keyBuffer: ArrayBuffer | undefined;
  let transientKey: CryptoKey | undefined;
  let nonce: Uint8Array | undefined;
  let nonceBuffer: ArrayBuffer | undefined;
  let aadBuffer: ArrayBuffer | undefined;

  try {
    aadBytes = encodeAad(aad);
    const webCrypto = getWebCrypto();

    keyBuffer = toArrayBuffer(keyToWrap);
    transientKey = await webCrypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: AES_256_KEY_BITS },
      true,
      ['encrypt'],
    );

    nonce = secureRandom(AES_GCM_NONCE_BYTES);
    nonceBuffer = toArrayBuffer(nonce);
    aadBuffer = toArrayBuffer(aadBytes);

    const wrappedBuffer = await webCrypto.subtle.wrapKey(
      'raw',
      transientKey,
      wrappingKey,
      {
        name: 'AES-GCM',
        iv: nonceBuffer,
        additionalData: aadBuffer,
        tagLength: AES_GCM_TAG_BITS,
      },
    );

    const ciphertextWithTag = new Uint8Array(wrappedBuffer);
    return encodeEnvelope(nonce, ciphertextWithTag, ENVELOPE_VERSION_V1);
  } finally {
    transientKey = undefined;
    wipeBuffers(keyBuffer, nonce, nonceBuffer, aadBuffer, aadBytes);
  }
}

/**
 * Unwraps a wrapped 256-bit AES-GCM key from its versioned binary envelope
 * using WebCrypto `subtle.unwrapKey('raw', ...)`, always importing the
 * resulting `CryptoKey` as **non-extractable** (`extractable = false`).
 *
 * Wrapping keys (`vault-key-*`) receive only `['wrapKey', 'unwrapKey']` usages;
 * leaf item keys (`item-key-*`) receive only `['encrypt', 'decrypt']` usages.
 * Mixing the two usage groups throws `CryptoArgumentError`.
 *
 * Any cryptographic or envelope failure (wrong wrapping key, tampered envelope,
 * wrong AAD, or malformed input) throws the single generic `DecryptionError`.
 */
export async function unwrapKey(
  wrappingKey: CryptoKey,
  wrappedEnvelope: Uint8Array,
  aad: KeyWrapAadParams,
  usages?: ReadonlyArray<KeyUsage>,
): Promise<CryptoKey> {
  if (
    !aad ||
    typeof aad !== 'object' ||
    !ALLOWED_WRAP_PURPOSES.has(aad.purpose)
  ) {
    throw new CryptoArgumentError();
  }
  if (usages !== undefined) {
    assertValidKeyUsages(usages);
  }

  let aadBytes: Uint8Array | undefined;
  let decoded: DecodedEnvelope | undefined;
  let nonceBuffer: ArrayBuffer | undefined;
  let aadBuffer: ArrayBuffer | undefined;
  let ciphertextBuffer: ArrayBuffer | undefined;

  try {
    if (
      !isAes256GcmWrappingKey(wrappingKey, 'unwrapKey') ||
      !(wrappedEnvelope instanceof Uint8Array) ||
      wrappedEnvelope.byteLength !== WRAPPED_KEY_ENVELOPE_BYTES
    ) {
      throw new DecryptionError();
    }

    aadBytes = encodeAad(aad);
    const expectedGroup: 'wrapping' | 'data' = VAULT_KEY_PURPOSES.has(
      aad.purpose,
    )
      ? 'wrapping'
      : 'data';
    const effectiveUsages: ReadonlyArray<KeyUsage> =
      usages ??
      (expectedGroup === 'wrapping'
        ? ['wrapKey', 'unwrapKey']
        : ['encrypt', 'decrypt']);
    assertValidKeyUsages(effectiveUsages, expectedGroup);

    decoded = decodeEnvelope(wrappedEnvelope);
    if (decoded.ciphertextWithTag.byteLength !== WRAPPED_KEY_CIPHERTEXT_BYTES) {
      throw new DecryptionError();
    }

    const webCrypto = getWebCrypto();
    nonceBuffer = toArrayBuffer(decoded.nonce);
    aadBuffer = toArrayBuffer(aadBytes);
    ciphertextBuffer = toArrayBuffer(decoded.ciphertextWithTag);

    return await webCrypto.subtle.unwrapKey(
      'raw',
      ciphertextBuffer,
      wrappingKey,
      {
        name: 'AES-GCM',
        iv: nonceBuffer,
        additionalData: aadBuffer,
        tagLength: AES_GCM_TAG_BITS,
      },
      {
        name: 'AES-GCM',
        length: AES_256_KEY_BITS,
      },
      false,
      [...effectiveUsages],
    );
  } catch {
    throw new DecryptionError();
  } finally {
    wipeBuffers(
      decoded?.nonce,
      decoded?.ciphertextWithTag,
      nonceBuffer,
      aadBuffer,
      ciphertextBuffer,
      aadBytes,
    );
  }
}

/**
 * Re-wraps a wrapped 256-bit key envelope from `oldWrappingKey` (`oldAad`) to
 * `newWrappingKey` (`newAad`) using WebCrypto `subtle.unwrapKey` into a
 * short-lived function-local `CryptoKey` followed immediately by
 * `subtle.wrapKey`, releasing the local key in `finally`.
 *
 * Security note: only for master-password change and passkey registration,
 * after fresh authentication. Never uses `decrypt` and never returns or stores
 * the transient extractable key.
 */
export async function rewrapKey(
  oldWrappingKey: CryptoKey,
  oldEnvelope: Uint8Array,
  oldAad: VaultKeyWrapAadParams,
  newWrappingKey: CryptoKey,
  newAad: VaultKeyWrapAadParams,
): Promise<Uint8Array> {
  let oldAadBytes: Uint8Array | undefined;
  let newAadBytes: Uint8Array | undefined;
  let oldDecoded: DecodedEnvelope | undefined;
  let oldNonceBuffer: ArrayBuffer | undefined;
  let oldAadBuffer: ArrayBuffer | undefined;
  let oldCiphertextBuffer: ArrayBuffer | undefined;
  let transientKey: CryptoKey | undefined;
  let newNonce: Uint8Array | undefined;
  let newNonceBuffer: ArrayBuffer | undefined;
  let newAadBuffer: ArrayBuffer | undefined;

  try {
    if (
      !isAes256GcmWrappingKey(oldWrappingKey, 'unwrapKey') ||
      !isAes256GcmWrappingKey(newWrappingKey, 'wrapKey') ||
      !(oldEnvelope instanceof Uint8Array) ||
      oldEnvelope.byteLength !== WRAPPED_KEY_ENVELOPE_BYTES
    ) {
      throw new DecryptionError();
    }

    if (
      !oldAad ||
      !newAad ||
      typeof oldAad !== 'object' ||
      typeof newAad !== 'object' ||
      !VAULT_KEY_PURPOSES.has(oldAad.purpose) ||
      !VAULT_KEY_PURPOSES.has(newAad.purpose)
    ) {
      throw new DecryptionError();
    }

    // Cross-slot checks: K_m only to K_m; K_s master or PRF only to K_s master or PRF
    if (oldAad.purpose === 'vault-key-km') {
      if (newAad.purpose !== 'vault-key-km') {
        throw new DecryptionError();
      }
    } else {
      if (
        newAad.purpose !== 'vault-key-ks-master' &&
        newAad.purpose !== 'vault-key-ks-prf'
      ) {
        throw new DecryptionError();
      }
    }

    // require the same userId (compare the encoded bytes)
    const oldUserBytes = toBoundedNonEmptyBytes(oldAad.userId);
    const newUserBytes = toBoundedNonEmptyBytes(newAad.userId);
    if (!constantTimeEqual(oldUserBytes, newUserBytes)) {
      throw new DecryptionError();
    }

    // newAad.keyVersion greater than or equal to oldAad.keyVersion
    if (newAad.keyVersion < oldAad.keyVersion) {
      throw new DecryptionError();
    }

    oldAadBytes = encodeAad(oldAad);
    newAadBytes = encodeAad(newAad);

    oldDecoded = decodeEnvelope(oldEnvelope);
    if (
      oldDecoded.ciphertextWithTag.byteLength !== WRAPPED_KEY_CIPHERTEXT_BYTES
    ) {
      throw new DecryptionError();
    }

    const webCrypto = getWebCrypto();
    oldNonceBuffer = toArrayBuffer(oldDecoded.nonce);
    oldAadBuffer = toArrayBuffer(oldAadBytes);
    oldCiphertextBuffer = toArrayBuffer(oldDecoded.ciphertextWithTag);

    transientKey = await webCrypto.subtle.unwrapKey(
      'raw',
      oldCiphertextBuffer,
      oldWrappingKey,
      {
        name: 'AES-GCM',
        iv: oldNonceBuffer,
        additionalData: oldAadBuffer,
        tagLength: AES_GCM_TAG_BITS,
      },
      {
        name: 'AES-GCM',
        length: AES_256_KEY_BITS,
      },
      true,
      ['wrapKey', 'unwrapKey'],
    );

    newNonce = secureRandom(AES_GCM_NONCE_BYTES);
    newNonceBuffer = toArrayBuffer(newNonce);
    newAadBuffer = toArrayBuffer(newAadBytes);

    const wrappedBuffer = await webCrypto.subtle.wrapKey(
      'raw',
      transientKey,
      newWrappingKey,
      {
        name: 'AES-GCM',
        iv: newNonceBuffer,
        additionalData: newAadBuffer,
        tagLength: AES_GCM_TAG_BITS,
      },
    );

    const ciphertextWithTag = new Uint8Array(wrappedBuffer);
    return encodeEnvelope(newNonce, ciphertextWithTag, ENVELOPE_VERSION_V1);
  } catch {
    throw new DecryptionError();
  } finally {
    transientKey = undefined;
    wipeBuffers(
      oldDecoded?.nonce,
      oldDecoded?.ciphertextWithTag,
      oldAadBytes,
      newAadBytes,
      oldNonceBuffer,
      oldAadBuffer,
      oldCiphertextBuffer,
      newNonce,
      newNonceBuffer,
      newAadBuffer,
    );
  }
}
