import { CryptoArgumentError, DecryptionError } from './errors.ts';

/**
 * Current binary envelope format version (PRD Section 5.3 & 12).
 */
export const ENVELOPE_VERSION_V1 = 0x01 as const;

/**
 * AES-256-GCM nonce length in bytes (96 bits = 12 bytes) per PRD Section 5.3.
 */
export const AES_GCM_NONCE_BYTES = 12 as const;

/**
 * AES-256-GCM authentication tag length in bytes (128 bits = 16 bytes).
 */
export const AES_GCM_TAG_BYTES = 16 as const;

/**
 * AES-256-GCM authentication tag length in bits (128 bits).
 */
export const AES_GCM_TAG_BITS = 128 as const;

/**
 * Header size of the binary envelope: 1 version byte + 12 nonce bytes = 13 bytes.
 */
export const ENVELOPE_HEADER_BYTES = 1 + AES_GCM_NONCE_BYTES;

/**
 * Total fixed byte overhead of an encrypted envelope:
 * 1 byte version + 12 bytes nonce + 16 bytes GCM tag = 29 bytes.
 */
export const ENVELOPE_OVERHEAD_BYTES = ENVELOPE_HEADER_BYTES + AES_GCM_TAG_BYTES;

/**
 * Decoded binary envelope components.
 */
export interface DecodedEnvelope {
  readonly version: number;
  readonly nonce: Uint8Array;
  readonly ciphertextWithTag: Uint8Array;
}

/**
 * Encodes a versioned binary envelope:
 * `[version (1 byte) || nonce (12 bytes) || ciphertext + tag (>= 16 bytes)]`
 */
export function encodeEnvelope(
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  version: number = ENVELOPE_VERSION_V1,
): Uint8Array {
  if (
    !(nonce instanceof Uint8Array) ||
    !(ciphertextWithTag instanceof Uint8Array) ||
    nonce.byteLength !== AES_GCM_NONCE_BYTES ||
    ciphertextWithTag.byteLength < AES_GCM_TAG_BYTES ||
    !Number.isSafeInteger(version) ||
    version < 1 ||
    version > 0xff
  ) {
    throw new CryptoArgumentError();
  }

  const out = new Uint8Array(1 + nonce.byteLength + ciphertextWithTag.byteLength);
  out[0] = version;
  out.set(nonce, 1);
  out.set(ciphertextWithTag, 1 + nonce.byteLength);
  return out;
}

/**
 * Decodes and validates a versioned binary envelope.
 * Throws `DecryptionError` if the envelope is truncated or has an unsupported
 * version byte.
 */
export function decodeEnvelope(envelope: Uint8Array): DecodedEnvelope {
  if (
    !(envelope instanceof Uint8Array) ||
    envelope.byteLength < ENVELOPE_OVERHEAD_BYTES
  ) {
    throw new DecryptionError();
  }

  const version = envelope[0];
  if (version !== ENVELOPE_VERSION_V1) {
    throw new DecryptionError();
  }

  const nonce = envelope.slice(1, 1 + AES_GCM_NONCE_BYTES);
  const ciphertextWithTag = envelope.slice(1 + AES_GCM_NONCE_BYTES);

  return {
    version,
    nonce,
    ciphertextWithTag,
  };
}
