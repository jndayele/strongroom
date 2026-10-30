import { CryptoArgumentError, InvalidSecretKeyError } from './errors.ts';
import { wipeBuffer } from './memory.ts';
import { secureRandom } from './random.ts';

/**
 * Secret Key entropy in bytes (128 bits = 16 bytes) per PRD Section 5.1.
 */
export const SECRET_KEY_BYTES = 16 as const;

/**
 * Version prefix for Strongroom Secret Keys (PRD Section 5.1).
 */
export const SECRET_KEY_PREFIX = 'A3' as const;

/**
 * RFC 4648 Base32 alphabet (uppercase A-Z and digits 2-7, 32 symbols).
 * Avoids visually ambiguous 0/O, 1/I, and 8/B pairings.
 */
export const SECRET_KEY_BASE32_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' as const;

/**
 * Group lengths after the `A3-` prefix: 6 + 6 + 5 + 5 + 5 = 27 Base32 chars
 * (27 * 5 = 135 bits = 128 bits random entropy + 7-bit CRC-7 checksum).
 */
export const SECRET_KEY_GROUP_LENGTHS = [6, 6, 5, 5, 5] as const;

/**
 * Total Base32 payload characters following the `A3` version prefix.
 */
export const SECRET_KEY_BASE32_CHARS = 27 as const;

/**
 * Maximum allowed input string length accepted by `parseSecretKey` before
 * any normalization or separator stripping.
 */
export const MAX_SECRET_KEY_INPUT_LENGTH = 128 as const;

/**
 * CRC-7 7-bit feedback polynomial tap mask for G(x) = x^7 + x^3 + 1 (0x09;
 * full degree-7 bit pattern 0x89) and initial 7-bit seed (0x5A).
 */
export const SECRET_KEY_CRC7_POLY = 0x09 as const;
export const SECRET_KEY_CRC7_SEED = 0x5a as const;

/**
 * Precomputed lookup table mapping ASCII character codes to 5-bit Base32 values
 * (-1 for invalid characters).
 */
const BASE32_LOOKUP: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < SECRET_KEY_BASE32_ALPHABET.length; i++) {
    const code = SECRET_KEY_BASE32_ALPHABET.charCodeAt(i);
    table[code] = i;
  }
  return table;
})();

/**
 * Computes a 7-bit CRC over the 128-bit raw Secret Key using the primitive
 * irreducible degree-7 polynomial G(x) = x^7 + x^3 + 1 (7-bit feedback tap
 * mask 0x09, full polynomial 0x89), pre-seeded with 0x5A (binding the A3
 * format prefix).
 *
 * Algebraic guarantee:
 * - Any single Base32 character substitution produces a 5-bit burst error
 *   E(x) = x^k * B(x) with deg(B) <= 4 < 7. Because G(x) is irreducible of
 *   degree 7, G(x) never divides E(x), so 100% of single-character errors
 *   (all 27 positions x 31 alternatives = 837 substitutions) are detected
 *   with zero false negatives.
 * - Because G(x) has primitive period 2^7 - 1 = 127 and gcd(5, 127) = 1,
 *   100% of two-character transpositions at any distance are also detected.
 */
function computeSecretKeyCrc7(rawKey: Uint8Array): number {
  let crc: number = SECRET_KEY_CRC7_SEED;
  for (let i = 0; i < rawKey.byteLength; i++) {
    const byte = rawKey[i] ?? 0;
    for (let bit = 7; bit >= 0; bit--) {
      const msb = ((crc >> 6) & 1) ^ ((byte >> bit) & 1);
      crc = (crc << 1) & 0x7f;
      if (msb !== 0) {
        crc ^= SECRET_KEY_CRC7_POLY;
      }
    }
  }
  return crc & 0x7f;
}

/**
 * Formats a 16-byte (128-bit) raw Secret Key into the hyphenated `A3-...`
 * representation (`6-6-5-5-5` Base32 groups) with an embedded 7-bit CRC-7
 * checksum.
 */
export function formatSecretKey(rawKey: Uint8Array): string {
  if (!(rawKey instanceof Uint8Array) || rawKey.byteLength !== SECRET_KEY_BYTES) {
    throw new CryptoArgumentError();
  }

  const crc7 = computeSecretKeyCrc7(rawKey);
  const chars: string[] = [];

  let bitBuffer = 0;
  let bitCount = 0;

  for (let i = 0; i < rawKey.byteLength; i++) {
    bitBuffer = (bitBuffer << 8) | (rawKey[i] ?? 0);
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      const index = (bitBuffer >> bitCount) & 0x1f;
      chars.push(SECRET_KEY_BASE32_ALPHABET[index] ?? '');
      bitBuffer &= (1 << bitCount) - 1;
    }
  }

  // Remaining 3 bits from rawKey (128 = 25 * 5 + 3) combined with 7-bit CRC = 10 bits (2 chars)
  bitBuffer = (bitBuffer << 7) | crc7;
  bitCount += 7;
  while (bitCount >= 5) {
    bitCount -= 5;
    const index = (bitBuffer >> bitCount) & 0x1f;
    chars.push(SECRET_KEY_BASE32_ALPHABET[index] ?? '');
    bitBuffer &= (1 << bitCount) - 1;
  }

  const groups: string[] = [SECRET_KEY_PREFIX];
  let offset = 0;
  for (const groupLen of SECRET_KEY_GROUP_LENGTHS) {
    groups.push(chars.slice(offset, offset + groupLen).join(''));
    offset += groupLen;
  }

  return groups.join('-');
}

/**
 * Generates a fresh 128-bit random Secret Key formatted with the `A3-` prefix
 * and embedded CRC-7 checksum (PRD Section 5.1).
 */
export function generateSecretKey(): string {
  const rawKey = secureRandom(SECRET_KEY_BYTES);
  try {
    return formatSecretKey(rawKey);
  } finally {
    wipeBuffer(rawKey);
  }
}

/**
 * Parses and validates a Secret Key string:
 * - Rejects any input longer than 128 characters before running any regex.
 * - Requires the contiguous `A3` version prefix before stripping separators.
 * - Strips hyphens and whitespace from the payload and normalizes lowercase to uppercase.
 * - Rejects any payload whose normalized length is not 27 Base32 characters.
 * - Validates the Base32 alphabet and 7-bit CRC-7 checksum.
 * - Returns the 16 raw bytes (128 bits) that feed HKDF key derivation.
 * - Never includes the input string in any thrown error message.
 */
export function parseSecretKey(input: string): Uint8Array {
  if (typeof input !== 'string' || input.length > MAX_SECRET_KEY_INPUT_LENGTH) {
    throw new InvalidSecretKeyError();
  }

  const trimmed = input.trim();
  if (trimmed.length < SECRET_KEY_PREFIX.length) {
    throw new InvalidSecretKeyError();
  }

  const prefix = trimmed.slice(0, SECRET_KEY_PREFIX.length).toUpperCase();
  if (prefix !== SECRET_KEY_PREFIX) {
    throw new InvalidSecretKeyError();
  }

  const payloadChars = trimmed
    .slice(SECRET_KEY_PREFIX.length)
    .replace(/[\s-]+/g, '')
    .toUpperCase();

  if (payloadChars.length !== SECRET_KEY_BASE32_CHARS) {
    throw new InvalidSecretKeyError();
  }
  const rawKey = new Uint8Array(SECRET_KEY_BYTES);
  let bitBuffer = 0;
  let bitCount = 0;
  let byteIndex = 0;

  for (let i = 0; i < payloadChars.length; i++) {
    const code = payloadChars.charCodeAt(i);
    const val = code < 128 ? (BASE32_LOOKUP[code] ?? -1) : -1;
    if (val < 0) {
      wipeBuffer(rawKey);
      throw new InvalidSecretKeyError();
    }

    bitBuffer = (bitBuffer << 5) | val;
    bitCount += 5;

    while (bitCount >= 8 && byteIndex < SECRET_KEY_BYTES) {
      bitCount -= 8;
      rawKey[byteIndex] = (bitBuffer >> bitCount) & 0xff;
      byteIndex++;
      bitBuffer &= (1 << bitCount) - 1;
    }
  }

  if (bitCount !== 7 || byteIndex !== SECRET_KEY_BYTES) {
    wipeBuffer(rawKey);
    throw new InvalidSecretKeyError();
  }

  const extractedCrc = bitBuffer & 0x7f;
  const expectedCrc = computeSecretKeyCrc7(rawKey);

  if ((extractedCrc ^ expectedCrc) !== 0) {
    wipeBuffer(rawKey);
    throw new InvalidSecretKeyError();
  }

  return rawKey;
}
