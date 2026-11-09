// Key generation and AES-256-GCM key wrapping/unwrapping with AAD (PRD Sections 5.2, 5.3, and 8).
//
// Security rules:
// - Unwrapped keys live in memory as non-extractable `CryptoKey` objects (`extractable: false`).
// - When generating a new key that must be wrapped for server storage (such as K_m, K_s, or an
//   item key), raw bytes exist only inside `generateAndWrapKey` or `wrapKey`, and the raw
//   buffer is immediately overwritten via `zeroize()` in a `finally` block.

import { AeadDecryptionError, aeadDecrypt, aeadEncrypt } from "./aead.ts";
import { randomBytes } from "./random.ts";
import { zeroize } from "./wipe.ts";

export const KEY_BYTE_LENGTH = 32 as const; // 256 bits

export interface GeneratedWrappedKey {
  /** Non-extractable in-memory AES-256-GCM CryptoKey ready for immediate client-side use. */
  readonly key: CryptoKey;
  /** Versioned AES-256-GCM envelope containing the wrapped 256-bit key bound to the caller's AAD. */
  readonly wrappedKey: Uint8Array<ArrayBuffer>;
}

export interface GeneratedVaultKeyPair {
  /** Vault Metadata Key (K_m), non-extractable in memory. */
  readonly km: CryptoKey;
  /** K_m wrapped under the KEK with AAD. */
  readonly wrappedKm: Uint8Array<ArrayBuffer>;
  /** Vault Secret Key (K_s), non-extractable in memory. */
  readonly ks: CryptoKey;
  /** K_s wrapped under the KEK with AAD. */
  readonly wrappedKs: Uint8Array<ArrayBuffer>;
}

/**
 * Imports raw 256-bit key bytes as a non-extractable AES-256-GCM `CryptoKey`
 * and zeroes the caller's raw key buffer in a `finally` block.
 */
export async function importNonExtractableAesGcmKey(
  rawKeyBytes: Uint8Array,
  usages: readonly KeyUsage[] = ["encrypt", "decrypt"]
): Promise<CryptoKey> {
  if (rawKeyBytes.byteLength !== KEY_BYTE_LENGTH) {
    zeroize(rawKeyBytes);
    throw new RangeError(
      `AES-256-GCM key must be ${String(KEY_BYTE_LENGTH)} bytes (256 bits), got ${String(rawKeyBytes.byteLength)}`
    );
  }

  const copy = new Uint8Array(KEY_BYTE_LENGTH);
  copy.set(rawKeyBytes);
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      copy,
      { name: "AES-GCM", length: 256 },
      false, // non-extractable
      [...usages]
    );
  } finally {
    zeroize(copy);
    zeroize(rawKeyBytes);
  }
}

/**
 * Generates a fresh random 256-bit non-extractable AES-256-GCM `CryptoKey`.
 */
export async function generateKey(
  usages: readonly KeyUsage[] = ["encrypt", "decrypt"]
): Promise<CryptoKey> {
  return await globalThis.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    [...usages]
  );
}

/**
 * Generates a random 256-bit key for a vault key (`K_m` or `K_s`).
 */
export async function generateVaultKey(): Promise<CryptoKey> {
  return await generateKey(["encrypt", "decrypt"]);
}

/**
 * Generates a random 256-bit per-item key.
 */
export async function generateItemKey(): Promise<CryptoKey> {
  return await generateKey(["encrypt", "decrypt"]);
}

/**
 * Wraps a 256-bit key under `wrappingKey` using AES-256-GCM with mandatory `aad`,
 * producing a versioned binary envelope.
 *
 * Accepts either:
 * - a `Uint8Array` of 32 raw key bytes (which is zeroized before this function returns), or
 * - an extractable `CryptoKey` (whose exported raw buffer is zeroized immediately after encryption).
 */
export async function wrapKey(
  wrappingKey: CryptoKey,
  keyToWrap: Uint8Array | CryptoKey,
  aad: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  if (keyToWrap instanceof Uint8Array) {
    try {
      if (keyToWrap.byteLength !== KEY_BYTE_LENGTH) {
        throw new RangeError(
          `wrapKey: raw key must be ${String(KEY_BYTE_LENGTH)} bytes, got ${String(keyToWrap.byteLength)}`
        );
      }
      return await aeadEncrypt(wrappingKey, keyToWrap, aad);
    } finally {
      zeroize(keyToWrap);
    }
  }

  if (!keyToWrap.extractable) {
    throw new TypeError(
      "wrapKey: cannot export a non-extractable CryptoKey; use generateAndWrapKey or pass raw bytes at generation time"
    );
  }

  const exportedBuffer = await globalThis.crypto.subtle.exportKey(
    "raw",
    keyToWrap
  );
  const rawBytes = new Uint8Array(exportedBuffer);
  try {
    if (rawBytes.byteLength !== KEY_BYTE_LENGTH) {
      throw new RangeError(
        `wrapKey: exported key must be ${String(KEY_BYTE_LENGTH)} bytes, got ${String(rawBytes.byteLength)}`
      );
    }
    return await aeadEncrypt(wrappingKey, rawBytes, aad);
  } finally {
    zeroize(rawBytes);
  }
}

/**
 * Unwraps a 256-bit AES-256-GCM key from `wrappedEnvelope` using `unwrappingKey` and mandatory `aad`.
 * The unwrapped key is imported as a **non-extractable** `CryptoKey` (`extractable: false`),
 * and the temporary decrypted raw bytes are immediately overwritten with zeros.
 */
export async function unwrapKey(
  unwrappingKey: CryptoKey,
  wrappedEnvelope: Uint8Array,
  aad: Uint8Array,
  usages: readonly KeyUsage[] = ["encrypt", "decrypt"]
): Promise<CryptoKey> {
  const decryptedBytes = await aeadDecrypt(
    unwrappingKey,
    wrappedEnvelope,
    aad
  );
  try {
    if (decryptedBytes.byteLength !== KEY_BYTE_LENGTH) {
      throw new AeadDecryptionError(
        `Unwrapped key has invalid length: ${String(decryptedBytes.byteLength)} bytes`
      );
    }
    return await importNonExtractableAesGcmKey(decryptedBytes, usages);
  } finally {
    zeroize(decryptedBytes);
  }
}

/**
 * Generates a fresh random 256-bit key, wraps it under `wrappingKey` with `aad`,
 * imports the in-memory copy as a **non-extractable** `CryptoKey`, and zeroes the
 * temporary raw key buffer before returning.
 */
export async function generateAndWrapKey(
  wrappingKey: CryptoKey,
  aad: Uint8Array,
  usages: readonly KeyUsage[] = ["encrypt", "decrypt"]
): Promise<GeneratedWrappedKey> {
  const rawKey = randomBytes(KEY_BYTE_LENGTH);
  const rawKeyForImport = new Uint8Array(KEY_BYTE_LENGTH);
  rawKeyForImport.set(rawKey);
  try {
    const wrappedKey = await wrapKey(wrappingKey, rawKey, aad);
    const key = await importNonExtractableAesGcmKey(rawKeyForImport, usages);
    return { key, wrappedKey };
  } finally {
    zeroize(rawKey);
    zeroize(rawKeyForImport);
  }
}

/**
 * Generates both random 256-bit vault keys (`K_m` and `K_s`), wraps each under `kek`
 * with its corresponding AAD, and returns non-extractable in-memory `CryptoKey` handles
 * alongside their wrapped envelopes.
 */
export async function generateAndWrapVaultKeys(
  kek: CryptoKey,
  kmAad: Uint8Array,
  ksAad: Uint8Array
): Promise<GeneratedVaultKeyPair> {
  const kmResult = await generateAndWrapKey(kek, kmAad);
  const ksResult = await generateAndWrapKey(kek, ksAad);
  return {
    km: kmResult.key,
    wrappedKm: kmResult.wrappedKey,
    ks: ksResult.key,
    wrappedKs: ksResult.wrappedKey,
  };
}
