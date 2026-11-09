// Versioned binary ciphertext envelope and 256-byte bucket plaintext padding (PRD Section 5.3).
//
// Wire layout of an encoded envelope:
//   [0]       version byte      (1 byte, currently 0x01)
//   [1]       algorithm id byte (1 byte, currently 0x01 = AES-256-GCM)
//   [2..14]   nonce             (12 bytes = 96-bit random IV)
//   [14..end] ciphertext + tag  (padded plaintext length + 16-byte GCM tag)
//
// Plaintext padding layout (before encryption):
//   [0..4]    true plaintext length as a 32-bit unsigned big-endian integer (4 bytes)
//   [4..4+L]  original plaintext bytes (L bytes)
//   [4+L..P]  zero padding bytes so total padded length P is a multiple of 256 bytes (P >= 256).
//
// Because AES-GCM is a stream cipher mode that adds a fixed 16-byte tag,
// a padded plaintext of `k * 256` bytes always produces a ciphertext+tag of `k * 256 + 16` bytes,
// and a total envelope of `k * 256 + 30` bytes.

export const ENVELOPE_VERSION_V1 = 0x01 as const;
export const ALGORITHM_ID_AES_256_GCM = 0x01 as const;

export const NONCE_BYTE_LENGTH = 12 as const;
export const GCM_TAG_BYTE_LENGTH = 16 as const;
export const ENVELOPE_HEADER_BYTE_LENGTH = 1 + 1 + NONCE_BYTE_LENGTH; // 14 bytes

export const PADDING_BUCKET_BYTES = 256 as const;
export const LENGTH_PREFIX_BYTES = 4 as const;

/**
 * Maximum allowed envelope size (64 KiB = 65,536 bytes), matching the PostgreSQL
 * `CHECK (octet_length(meta_blob) <= 65536)` constraint in `0001_initial_schema.sql`.
 */
export const MAX_ENVELOPE_BYTE_LENGTH = 65_536 as const;

/**
 * Maximum unpadded plaintext length that fits inside a 64 KiB envelope after
 * adding the 4-byte length prefix, rounding up to a 256-byte bucket, and adding
 * the 14-byte header + 16-byte GCM tag:
 *   max padded plaintext = 255 * 256 = 65,280 bytes (envelope = 65,310 <= 65,536)
 *   max unpadded plaintext = 65,280 - 4 = 65,276 bytes.
 */
export const MAX_PLAINTEXT_BYTE_LENGTH =
  Math.floor(
    (MAX_ENVELOPE_BYTE_LENGTH -
      ENVELOPE_HEADER_BYTE_LENGTH -
      GCM_TAG_BYTE_LENGTH) /
      PADDING_BUCKET_BYTES
  ) *
    PADDING_BUCKET_BYTES -
  LENGTH_PREFIX_BYTES;

export type EnvelopeErrorCode =
  | "TRUNCATED_DATA"
  | "OVERSIZED_DATA"
  | "UNKNOWN_VERSION"
  | "UNKNOWN_ALGORITHM"
  | "INVALID_NONCE_LENGTH"
  | "INVALID_PADDING";

export class EnvelopeError extends Error {
  public readonly code: EnvelopeErrorCode;

  public constructor(code: EnvelopeErrorCode, message: string) {
    super(message);
    this.name = "EnvelopeError";
    this.code = code;
  }
}

export interface DecodedEnvelope {
  readonly version: typeof ENVELOPE_VERSION_V1;
  readonly algorithmId: typeof ALGORITHM_ID_AES_256_GCM;
  readonly nonce: Uint8Array<ArrayBuffer>;
  readonly ciphertextAndTag: Uint8Array<ArrayBuffer>;
}

/**
 * Pads `plaintext` to a multiple of 256 bytes (`PADDING_BUCKET_BYTES`), storing the
 * true byte length in the first 4 bytes (big-endian uint32).
 */
export function padPlaintext(
  plaintext: Uint8Array
): Uint8Array<ArrayBuffer> {
  const trueLength = plaintext.byteLength;
  if (trueLength > MAX_PLAINTEXT_BYTE_LENGTH) {
    throw new EnvelopeError(
      "OVERSIZED_DATA",
      `Plaintext length (${String(trueLength)}) exceeds maximum allowed (${String(MAX_PLAINTEXT_BYTE_LENGTH)} bytes)`
    );
  }

  const requiredBytes = LENGTH_PREFIX_BYTES + trueLength;
  const bucketCount = Math.max(
    1,
    Math.ceil(requiredBytes / PADDING_BUCKET_BYTES)
  );
  const paddedLength = bucketCount * PADDING_BUCKET_BYTES;

  const padded = new Uint8Array(paddedLength);
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  view.setUint32(0, trueLength, false); // big-endian
  padded.set(plaintext, LENGTH_PREFIX_BYTES);
  // Remaining bytes in `padded` are already 0-initialized by `new Uint8Array(paddedLength)`.
  return padded;
}

/**
 * Strips the 256-byte bucket padding added by `padPlaintext` and validates the
 * embedded length prefix and zero-padding tail.
 */
export function unpadPlaintext(
  padded: Uint8Array
): Uint8Array<ArrayBuffer> {
  const paddedLength = padded.byteLength;
  if (
    paddedLength < PADDING_BUCKET_BYTES ||
    paddedLength % PADDING_BUCKET_BYTES !== 0
  ) {
    throw new EnvelopeError(
      "INVALID_PADDING",
      `Padded plaintext length (${String(paddedLength)}) is not a positive multiple of ${String(PADDING_BUCKET_BYTES)}`
    );
  }

  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const trueLength = view.getUint32(0, false); // big-endian

  if (trueLength > MAX_PLAINTEXT_BYTE_LENGTH) {
    throw new EnvelopeError(
      "INVALID_PADDING",
      `Embedded plaintext length (${String(trueLength)}) exceeds maximum (${String(MAX_PLAINTEXT_BYTE_LENGTH)})`
    );
  }

  const requiredBytes = LENGTH_PREFIX_BYTES + trueLength;
  if (requiredBytes > paddedLength) {
    throw new EnvelopeError(
      "INVALID_PADDING",
      `Embedded plaintext length (${String(trueLength)}) exceeds padded buffer capacity (${String(paddedLength - LENGTH_PREFIX_BYTES)})`
    );
  }

  // Enforce minimal bucket count: the padded buffer must be the exact bucket for `trueLength`.
  const expectedBuckets = Math.max(
    1,
    Math.ceil(requiredBytes / PADDING_BUCKET_BYTES)
  );
  if (paddedLength !== expectedBuckets * PADDING_BUCKET_BYTES) {
    throw new EnvelopeError(
      "INVALID_PADDING",
      `Padded plaintext uses ${String(paddedLength)} bytes, expected ${String(expectedBuckets * PADDING_BUCKET_BYTES)} bytes for length ${String(trueLength)}`
    );
  }

  // Verify that all trailing pad bytes are zero.
  let nonZeroPadMask = 0;
  for (let i = requiredBytes; i < paddedLength; i++) {
    nonZeroPadMask |= padded[i] ?? 0;
  }
  if (nonZeroPadMask !== 0) {
    throw new EnvelopeError(
      "INVALID_PADDING",
      "Non-zero byte found in plaintext padding tail"
    );
  }

  const result = new Uint8Array(trueLength);
  result.set(padded.subarray(LENGTH_PREFIX_BYTES, requiredBytes));
  return result;
}

/**
 * Encodes a versioned binary envelope:
 * `[version (1B)][algorithmId (1B)][nonce (12B)][ciphertext+tag]`
 */
export function encodeEnvelope(
  nonce: Uint8Array,
  ciphertextAndTag: Uint8Array,
  version: number = ENVELOPE_VERSION_V1,
  algorithmId: number = ALGORITHM_ID_AES_256_GCM
): Uint8Array<ArrayBuffer> {
  if (version !== ENVELOPE_VERSION_V1) {
    throw new EnvelopeError(
      "UNKNOWN_VERSION",
      `Unsupported envelope version: ${String(version)}`
    );
  }

  if (algorithmId !== ALGORITHM_ID_AES_256_GCM) {
    throw new EnvelopeError(
      "UNKNOWN_ALGORITHM",
      `Unsupported algorithm id: ${String(algorithmId)}`
    );
  }

  if (nonce.byteLength !== NONCE_BYTE_LENGTH) {
    throw new EnvelopeError(
      "INVALID_NONCE_LENGTH",
      `Nonce must be ${String(NONCE_BYTE_LENGTH)} bytes, got ${String(nonce.byteLength)}`
    );
  }

  const minCiphertextLength = PADDING_BUCKET_BYTES + GCM_TAG_BYTE_LENGTH;
  if (ciphertextAndTag.byteLength < minCiphertextLength) {
    throw new EnvelopeError(
      "TRUNCATED_DATA",
      `Ciphertext+tag (${String(ciphertextAndTag.byteLength)} bytes) is shorter than minimum (${String(minCiphertextLength)} bytes)`
    );
  }

  const paddedPlaintextLength =
    ciphertextAndTag.byteLength - GCM_TAG_BYTE_LENGTH;
  if (paddedPlaintextLength % PADDING_BUCKET_BYTES !== 0) {
    throw new EnvelopeError(
      "INVALID_PADDING",
      `Ciphertext payload length (${String(paddedPlaintextLength)}) is not a multiple of ${String(PADDING_BUCKET_BYTES)} bytes`
    );
  }

  const totalLength = ENVELOPE_HEADER_BYTE_LENGTH + ciphertextAndTag.byteLength;
  if (totalLength > MAX_ENVELOPE_BYTE_LENGTH) {
    throw new EnvelopeError(
      "OVERSIZED_DATA",
      `Envelope length (${String(totalLength)}) exceeds maximum (${String(MAX_ENVELOPE_BYTE_LENGTH)} bytes)`
    );
  }

  const out = new Uint8Array(totalLength);
  out[0] = version;
  out[1] = algorithmId;
  out.set(nonce, 2);
  out.set(ciphertextAndTag, ENVELOPE_HEADER_BYTE_LENGTH);
  return out;
}

/**
 * Strictly validates and decodes a binary envelope into its header fields, nonce, and ciphertext+tag.
 * Rejects unknown versions, unknown algorithm IDs, truncated data, and oversized data.
 */
export function decodeEnvelope(envelope: Uint8Array): DecodedEnvelope {
  if (envelope.byteLength > MAX_ENVELOPE_BYTE_LENGTH) {
    throw new EnvelopeError(
      "OVERSIZED_DATA",
      `Envelope length (${String(envelope.byteLength)}) exceeds maximum (${String(MAX_ENVELOPE_BYTE_LENGTH)} bytes)`
    );
  }

  // Check minimum header (2 bytes) first so version/algorithm errors are reported clearly
  // unless the input is completely empty or only 1 byte.
  if (envelope.byteLength < 2) {
    throw new EnvelopeError(
      "TRUNCATED_DATA",
      `Envelope is truncated (${String(envelope.byteLength)} bytes)`
    );
  }

  const version = envelope[0];
  if (version !== ENVELOPE_VERSION_V1) {
    throw new EnvelopeError(
      "UNKNOWN_VERSION",
      `Unknown envelope version: ${String(version)}`
    );
  }

  const algorithmId = envelope[1];
  if (algorithmId !== ALGORITHM_ID_AES_256_GCM) {
    throw new EnvelopeError(
      "UNKNOWN_ALGORITHM",
      `Unknown envelope algorithm id: ${String(algorithmId)}`
    );
  }

  const minTotalLength =
    ENVELOPE_HEADER_BYTE_LENGTH + PADDING_BUCKET_BYTES + GCM_TAG_BYTE_LENGTH;
  if (envelope.byteLength < minTotalLength) {
    throw new EnvelopeError(
      "TRUNCATED_DATA",
      `Envelope (${String(envelope.byteLength)} bytes) is shorter than minimum valid length (${String(minTotalLength)} bytes)`
    );
  }

  const ciphertextAndTagLength =
    envelope.byteLength - ENVELOPE_HEADER_BYTE_LENGTH;
  const paddedPlaintextLength = ciphertextAndTagLength - GCM_TAG_BYTE_LENGTH;
  if (paddedPlaintextLength % PADDING_BUCKET_BYTES !== 0) {
    throw new EnvelopeError(
      "TRUNCATED_DATA",
      `Envelope ciphertext payload (${String(paddedPlaintextLength)} bytes) is not aligned to ${String(PADDING_BUCKET_BYTES)}-byte padding buckets`
    );
  }

  const nonce = new Uint8Array(NONCE_BYTE_LENGTH);
  nonce.set(envelope.subarray(2, ENVELOPE_HEADER_BYTE_LENGTH));

  const ciphertextAndTag = new Uint8Array(ciphertextAndTagLength);
  ciphertextAndTag.set(envelope.subarray(ENVELOPE_HEADER_BYTE_LENGTH));

  return {
    version: ENVELOPE_VERSION_V1,
    algorithmId: ALGORITHM_ID_AES_256_GCM,
    nonce,
    ciphertextAndTag,
  };
}
