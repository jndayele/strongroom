// Cryptographically secure random number generation using the platform WebCrypto API.
// Never uses Math.random (PRD Sections 3 and 8).

const MAX_GET_RANDOM_VALUES_BYTES = 65_536;
const UINT32_RANGE = 0x1_0000_0000; // 2^32 = 4,294,967,296

/**
 * Generates `length` cryptographically strong random bytes using `crypto.getRandomValues`.
 * Handles buffers larger than 65,536 bytes by chunking, as required by the WebCrypto QuotaExceededError limit.
 */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError(
      `randomBytes: length must be a non-negative safe integer, got ${String(length)}`
    );
  }

  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += MAX_GET_RANDOM_VALUES_BYTES) {
    const chunkLength = Math.min(MAX_GET_RANDOM_VALUES_BYTES, length - offset);
    globalThis.crypto.getRandomValues(
      out.subarray(offset, offset + chunkLength)
    );
  }
  return out;
}

/**
 * Returns a uniformly distributed random integer in the range `[0, max)` (`0 <= result < max`)
 * using rejection sampling over 32-bit unsigned random values to eliminate modulo bias.
 *
 * Used by the password generator and recovery code generator (PRD Section 8).
 */
export function randomInt(max: number): number {
  if (!Number.isSafeInteger(max) || max <= 0 || max > UINT32_RANGE) {
    throw new RangeError(
      `randomInt: max must be an integer in [1, 2^32], got ${String(max)}`
    );
  }

  if (max === 1) {
    return 0;
  }

  // Largest multiple of `max` that fits in [0, 2^32).
  // Any random uint32 >= limit falls in the incomplete tail bucket and is rejected,
  // ensuring every remainder in [0, max) has identical probability.
  const remainder = UINT32_RANGE % max;
  const limit = UINT32_RANGE - remainder;

  const sampleBuffer = new Uint32Array(1);
  while (true) {
    globalThis.crypto.getRandomValues(sampleBuffer);
    const candidate = sampleBuffer[0];
    if (candidate !== undefined && candidate < limit) {
      sampleBuffer[0] = 0;
      return candidate % max;
    }
  }
}
