import { CryptoArgumentError } from './errors.ts';
import { getWebCrypto } from './memory.ts';

/**
 * Maximum bytes WebCrypto's `crypto.getRandomValues` accepts in a single call
 * per the W3C Web Cryptography API specification (65,536 bytes).
 */
const MAX_GET_RANDOM_VALUES_BYTES = 65_536;

/**
 * Upper sanity bound (16 MiB) for a single secureRandom allocation.
 */
const MAX_SECURE_RANDOM_BYTES = 16 * 1024 * 1024;

/**
 * Generates `n` cryptographically secure random bytes using `crypto.getRandomValues`.
 *
 * @param n Number of random bytes to generate (safe integer, 0 <= n <= 16 MiB).
 */
export function secureRandom(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_SECURE_RANDOM_BYTES) {
    throw new CryptoArgumentError();
  }
  const webCrypto = getWebCrypto();
  const out = new Uint8Array(n);
  if (n === 0) {
    return out;
  }
  for (let offset = 0; offset < n; offset += MAX_GET_RANDOM_VALUES_BYTES) {
    const chunkLength = Math.min(MAX_GET_RANDOM_VALUES_BYTES, n - offset);
    const view = new Uint8Array(out.buffer, offset, chunkLength);
    webCrypto.getRandomValues(view);
  }
  return out;
}
