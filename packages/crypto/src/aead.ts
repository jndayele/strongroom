// AES-256-GCM authenticated encryption and decryption using native WebCrypto (PRD Sections 3 and 5.3).
//
// Security invariants:
// - A fresh 96-bit (12-byte) random nonce is generated via `crypto.getRandomValues` on every encryption.
// - Non-empty AAD is mandatory (not optional) on every encrypt and decrypt call.
// - Plaintext is padded to 256-byte buckets before encryption, and unpadded after authentication succeeds.
// - Temporary padded plaintext buffers are overwritten with zeros immediately after use.

import {
  decodeEnvelope,
  encodeEnvelope,
  GCM_TAG_BYTE_LENGTH,
  NONCE_BYTE_LENGTH,
  padPlaintext,
  unpadPlaintext,
} from "./envelope.ts";
import { randomBytes } from "./random.ts";
import { zeroize } from "./wipe.ts";

export class AeadDecryptionError extends Error {
  public constructor(message = "AES-256-GCM authentication or decryption failed") {
    super(message);
    this.name = "AeadDecryptionError";
  }
}

function assertValidAesGcmKey(key: CryptoKey, requiredUsage: KeyUsage): void {
  if (key.type !== "secret" || key.algorithm.name !== "AES-GCM") {
    throw new TypeError("AES-256-GCM requires a secret AES-GCM CryptoKey");
  }
  const aesAlgorithm = key.algorithm as AesKeyAlgorithm;
  if (aesAlgorithm.length !== 256) {
    throw new TypeError(
      `AES-256-GCM requires a 256-bit key, got ${String(aesAlgorithm.length)}-bit`
    );
  }
  if (!key.usages.includes(requiredUsage)) {
    throw new TypeError(
      `AES-256-GCM key does not permit '${requiredUsage}' operation`
    );
  }
}

function assertNonEmptyAad(aad: Uint8Array): void {
  if (aad.byteLength === 0) {
    throw new RangeError(
      "AES-256-GCM AAD is required and must be non-empty"
    );
  }
}

function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer) {
    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

/**
 * Encrypts `plaintext` with `key` (256-bit AES-GCM `CryptoKey`) and mandatory `aad`,
 * padding the plaintext to 256-byte buckets and returning a versioned binary envelope.
 */
export async function aeadEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  assertValidAesGcmKey(key, "encrypt");
  assertNonEmptyAad(aad);

  const nonce = randomBytes(NONCE_BYTE_LENGTH);
  const paddedPlaintext = padPlaintext(plaintext);
  try {
    const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: toBufferSource(aad),
        tagLength: GCM_TAG_BYTE_LENGTH * 8,
      },
      key,
      paddedPlaintext
    );
    return encodeEnvelope(nonce, new Uint8Array(ciphertextBuffer));
  } finally {
    zeroize(paddedPlaintext);
  }
}

/**
 * Decrypts and authenticates a versioned binary `envelope` with `key` (256-bit AES-GCM `CryptoKey`)
 * and mandatory `aad`. Throws `EnvelopeError` on malformed envelopes or `AeadDecryptionError`
 * if authentication fails (tampered ciphertext, wrong key, or mismatched AAD).
 */
export async function aeadDecrypt(
  key: CryptoKey,
  envelope: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  assertValidAesGcmKey(key, "decrypt");
  assertNonEmptyAad(aad);

  const decoded = decodeEnvelope(envelope);
  let decryptedBuffer: ArrayBuffer;
  try {
    decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decoded.nonce,
        additionalData: toBufferSource(aad),
        tagLength: GCM_TAG_BYTE_LENGTH * 8,
      },
      key,
      decoded.ciphertextAndTag
    );
  } catch {
    throw new AeadDecryptionError();
  }

  const paddedPlaintext = new Uint8Array(decryptedBuffer);
  try {
    return unpadPlaintext(paddedPlaintext);
  } finally {
    zeroize(paddedPlaintext);
  }
}
