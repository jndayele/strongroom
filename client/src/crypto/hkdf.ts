import { CryptoArgumentError } from './errors.ts';
import { getWebCrypto, toArrayBuffer, wipeBuffers } from './memory.ts';

/**
 * SHA-256 digest length in bytes.
 */
export const HKDF_SHA256_HASH_LEN = 32 as const;

/**
 * Maximum output key material (OKM) length in bytes for HKDF-SHA-256
 * per RFC 5869 Section 2.3 (255 * HashLen = 8,160 bytes).
 */
export const HKDF_SHA256_MAX_LENGTH = 255 * HKDF_SHA256_HASH_LEN;

/**
 * Domain separation info string for the Key Encryption Key (PRD Section 5.2).
 */
export const VAULT_KEK_INFO = 'vault-kek-v1' as const;

/**
 * Domain separation info string and byte length for OPAQUE password input
 * (`pw_input`, PRD Section 5.2).
 */
export const PASSWORD_INPUT_INFO = 'strongroom-pw-input-v1' as const;
export const PASSWORD_INPUT_BYTES = 32 as const;

/**
 * Derives `length` bytes of output keying material using WebCrypto HKDF-SHA-256
 * (RFC 5869).
 *
 * @param ikm Input keying material (must be non-empty).
 * @param salt Optional salt value (if empty, RFC 5869 defaults to 32 zero bytes).
 * @param info Context and application specific information (may be empty).
 * @param length Desired output length in bytes (1 <= length <= 8160).
 */
export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (
    !(ikm instanceof Uint8Array) ||
    !(salt instanceof Uint8Array) ||
    !(info instanceof Uint8Array) ||
    ikm.byteLength === 0 ||
    !Number.isSafeInteger(length) ||
    length <= 0 ||
    length > HKDF_SHA256_MAX_LENGTH
  ) {
    throw new CryptoArgumentError();
  }

  let ikmBuffer: ArrayBuffer | undefined;
  let effectiveSalt: Uint8Array | undefined;
  let saltBuffer: ArrayBuffer | undefined;
  let infoBuffer: ArrayBuffer | undefined;

  try {
    const webCrypto = getWebCrypto();
    ikmBuffer = toArrayBuffer(ikm);
    effectiveSalt =
      salt.byteLength === 0 ? new Uint8Array(HKDF_SHA256_HASH_LEN) : salt;
    saltBuffer = toArrayBuffer(effectiveSalt);
    infoBuffer = toArrayBuffer(info);

    const baseKey = await webCrypto.subtle.importKey(
      'raw',
      ikmBuffer,
      'HKDF',
      false,
      ['deriveBits'],
    );

    const derivedBits = await webCrypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: saltBuffer,
        info: infoBuffer,
      },
      baseKey,
      length * 8,
    );

    return new Uint8Array(derivedBits);
  } finally {
    wipeBuffers(ikmBuffer, saltBuffer, infoBuffer);
    if (salt.byteLength === 0) {
      wipeBuffers(effectiveSalt);
    }
  }
}

/**
 * Derives the 32-byte OPAQUE password input (`pw_input`) using
 * `HKDF-SHA-256(ikm = NFKC-normalized UTF-8 master password, salt = 16 raw Secret Key bytes, info = "strongroom-pw-input-v1", 32 bytes)`
 * per PRD Section 5.2.
 */
export async function derivePasswordInput(
  masterPassword: string,
  secretKey: Uint8Array,
): Promise<Uint8Array> {
  if (
    typeof masterPassword !== 'string' ||
    !(secretKey instanceof Uint8Array) ||
    secretKey.byteLength !== 16
  ) {
    throw new CryptoArgumentError();
  }

  const normalizedPassword = masterPassword.normalize('NFKC');
  if (normalizedPassword.length === 0) {
    throw new CryptoArgumentError();
  }

  let passwordBytes: Uint8Array | undefined;
  let infoBytes: Uint8Array | undefined;

  try {
    passwordBytes = new TextEncoder().encode(normalizedPassword);
    infoBytes = new TextEncoder().encode(PASSWORD_INPUT_INFO);
    return await hkdf(
      passwordBytes,
      secretKey,
      infoBytes,
      PASSWORD_INPUT_BYTES,
    );
  } finally {
    wipeBuffers(passwordBytes, infoBytes);
  }
}

/**
 * Derives the non-extractable AES-256-GCM Key Encryption Key (KEK) directly
 * inside WebCrypto using HKDF-SHA-256(export_key, secret_key, "vault-kek-v1")
 * per PRD Section 5.2.
 *
 * KEK is a wrapping key only (`['wrapKey', 'unwrapKey']`); it never receives
 * `'encrypt'` or `'decrypt'` usages.
 */
export async function deriveKek(
  exportKey: Uint8Array,
  secretKey: Uint8Array,
): Promise<CryptoKey> {
  if (
    !(exportKey instanceof Uint8Array) ||
    !(secretKey instanceof Uint8Array) ||
    exportKey.byteLength === 0 ||
    secretKey.byteLength !== 16
  ) {
    throw new CryptoArgumentError();
  }

  let ikmBuffer: ArrayBuffer | undefined;
  let saltBuffer: ArrayBuffer | undefined;
  let infoBytes: Uint8Array | undefined;
  let infoBuffer: ArrayBuffer | undefined;

  try {
    const webCrypto = getWebCrypto();
    ikmBuffer = toArrayBuffer(exportKey);
    saltBuffer = toArrayBuffer(secretKey);
    infoBytes = new TextEncoder().encode(VAULT_KEK_INFO);
    infoBuffer = toArrayBuffer(infoBytes);

    const baseKey = await webCrypto.subtle.importKey(
      'raw',
      ikmBuffer,
      'HKDF',
      false,
      ['deriveKey'],
    );

    return await webCrypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: saltBuffer,
        info: infoBuffer,
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['wrapKey', 'unwrapKey'],
    );
  } finally {
    wipeBuffers(ikmBuffer, saltBuffer, infoBytes, infoBuffer);
  }
}
