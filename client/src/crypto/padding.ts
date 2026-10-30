import { CryptoArgumentError, DecryptionError } from './errors.ts';

/**
 * Bucket size in bytes for padded ciphertexts (PRD Section 5.3 & 12).
 */
export const PADDING_BUCKET_BYTES = 256 as const;

/**
 * 4-byte big-endian length prefix stored inside the padded plaintext.
 */
export const PADDING_LENGTH_PREFIX_BYTES = 4 as const;

/**
 * Maximum allowed plaintext size in bytes (1 MiB = 1,048,576 bytes).
 */
export const MAX_PLAINTEXT_BYTES = 1024 * 1024;

/**
 * Computes the maximum valid padded buffer byte length for a given `overheadBytes`.
 */
export function maxPaddedBytesForOverhead(overheadBytes: number = 0): number {
  if (
    !Number.isSafeInteger(overheadBytes) ||
    overheadBytes < 0 ||
    overheadBytes >= PADDING_BUCKET_BYTES
  ) {
    throw new CryptoArgumentError();
  }
  const maxRawRequired =
    PADDING_LENGTH_PREFIX_BYTES + MAX_PLAINTEXT_BYTES + overheadBytes;
  const maxBucketCount = Math.ceil(maxRawRequired / PADDING_BUCKET_BYTES);
  return maxBucketCount * PADDING_BUCKET_BYTES - overheadBytes;
}

/**
 * Pads `plaintext` into a 256-byte bucket structure:
 * `[u32_be(plaintext.byteLength) || plaintext || 0x00...0x00]`
 *
 * When `overheadBytes` is provided (e.g., 29 bytes for the versioned AES-GCM
 * envelope), the returned padded buffer has length `256 * k - overheadBytes`
 * so the resulting encrypted envelope is an exact multiple of 256 bytes.
 * When `overheadBytes` is 0 (the default), the returned padded buffer itself
 * is an exact multiple of 256 bytes.
 */
export function padToBucket(
  plaintext: Uint8Array,
  overheadBytes: number = 0,
): Uint8Array {
  if (
    !(plaintext instanceof Uint8Array) ||
    plaintext.byteLength > MAX_PLAINTEXT_BYTES ||
    !Number.isSafeInteger(overheadBytes) ||
    overheadBytes < 0 ||
    overheadBytes >= PADDING_BUCKET_BYTES
  ) {
    throw new CryptoArgumentError();
  }

  const rawRequired =
    PADDING_LENGTH_PREFIX_BYTES + plaintext.byteLength + overheadBytes;
  const bucketCount = Math.max(
    1,
    Math.ceil(rawRequired / PADDING_BUCKET_BYTES),
  );
  const totalPaddedWithOverhead = bucketCount * PADDING_BUCKET_BYTES;
  const paddedLength = totalPaddedWithOverhead - overheadBytes;

  const out = new Uint8Array(paddedLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(0, plaintext.byteLength, false);
  out.set(plaintext, PADDING_LENGTH_PREFIX_BYTES);

  return out;
}

/**
 * Validates and removes 256-byte bucket padding.
 *
 * Security note: Padding is validated only after AES-256-GCM authentication
 * succeeds; unauthenticated ciphertexts never reach this function during
 * decryption.
 *
 * Rejects with the generic `DecryptionError` if:
 * - the buffer is not a `Uint8Array`, is smaller than 4 bytes, or exceeds the
 *   maximum padded size for a 1 MiB plaintext,
 * - `(padded.byteLength + overheadBytes)` is not a positive multiple of 256,
 * - the 4-byte length header exceeds `MAX_PLAINTEXT_BYTES` (1 MiB) or exceeds
 *   the available buffer payload (`padded.byteLength - 4`),
 * - the buffer has non-minimal bucket padding (>= 256 trailing padding bytes),
 * - any trailing padding byte is non-zero.
 */
export function unpadFromBucket(
  padded: Uint8Array,
  overheadBytes: number = 0,
): Uint8Array {
  if (
    !(padded instanceof Uint8Array) ||
    !Number.isSafeInteger(overheadBytes) ||
    overheadBytes < 0 ||
    overheadBytes >= PADDING_BUCKET_BYTES
  ) {
    throw new DecryptionError();
  }

  const maxPaddedLength = maxPaddedBytesForOverhead(overheadBytes);
  const totalSize = padded.byteLength + overheadBytes;
  if (
    padded.byteLength < PADDING_LENGTH_PREFIX_BYTES ||
    padded.byteLength > maxPaddedLength ||
    totalSize <= 0 ||
    totalSize % PADDING_BUCKET_BYTES !== 0
  ) {
    throw new DecryptionError();
  }

  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const originalLength = view.getUint32(0, false);
  const availableBytes = padded.byteLength - PADDING_LENGTH_PREFIX_BYTES;

  if (originalLength > availableBytes || originalLength > MAX_PLAINTEXT_BYTES) {
    throw new DecryptionError();
  }

  const paddingBytesCount = availableBytes - originalLength;
  if (paddingBytesCount >= PADDING_BUCKET_BYTES) {
    throw new DecryptionError();
  }

  let nonZeroAccumulator = 0;
  for (
    let i = PADDING_LENGTH_PREFIX_BYTES + originalLength;
    i < padded.byteLength;
    i++
  ) {
    nonZeroAccumulator |= padded[i] ?? 0;
  }

  if (nonZeroAccumulator !== 0) {
    throw new DecryptionError();
  }

  return padded.slice(
    PADDING_LENGTH_PREFIX_BYTES,
    PADDING_LENGTH_PREFIX_BYTES + originalLength,
  );
}
