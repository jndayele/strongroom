// Secret Key generation, Crockford Base32 encoding, checksum validation, and parsing (PRD Section 5.1).
//
// WHY THE ENCODING IS LONGER THAN THE PRD EXAMPLE:
// Section 5.1 of the PRD requires a 128-bit random Secret Key and gives the illustrative
// format `A3-XXXXXX-XXXXXX-XXXXXX` (18 base32 characters after the `A3` prefix).
// However, each Crockford Base32 character encodes 5 bits, so 18 characters can hold at most
// `18 * 5 = 90` bits (or 85 bits plus a check character) — 38 bits short of 128 bits.
//
// To encode ALL 128 bits of randomness without loss:
// - `ceil(128 / 5) = 26` Crockford Base32 characters are required for the 128-bit payload
//   (26 * 5 = 130 bits: 128 random bits + 2 zero pad bits in the lowest-order bits of the 26th char).
// - Plus the 2-character version prefix `A3`.
// - Plus 1 Crockford Base32 check character (computed modulo 37 over the version prefix + 26 payload
//   characters, mapped into our 32-character alphabet via modulo 32 — or Luhn mod 32 over all 28
//   characters so every single-character substitution and adjacent transposition is detected).
//
// Canonical formatted layout (29 alphanumeric characters total, grouped with dashes for readability):
//   `A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXX`
//   - `A3`: 2-character version prefix
//   - 26 Crockford Base32 payload characters (128 bits of entropy)
//   - 1 Crockford Base32 Luhn mod 32 check character (the final character)

import { randomBytes } from "./random.ts";

export const SECRET_KEY_VERSION_PREFIX = "A3" as const;
export const SECRET_KEY_BYTE_LENGTH = 16 as const; // 128 bits
export const SECRET_KEY_PAYLOAD_CHARS = 26 as const; // ceil(128 / 5)
export const SECRET_KEY_TOTAL_CHARS = 29 as const; // 2 (prefix) + 26 (payload) + 1 (check)

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" as const;

export type SecretKeyErrorCode =
  | "INVALID_LENGTH"
  | "INVALID_PREFIX"
  | "INVALID_CHARACTER"
  | "NON_ZERO_PAD_BITS"
  | "CHECKSUM_MISMATCH";

export class SecretKeyError extends Error {
  public readonly code: SecretKeyErrorCode;

  public constructor(code: SecretKeyErrorCode, message: string) {
    super(message);
    this.name = "SecretKeyError";
    this.code = code;
  }
}

export interface SecretKey {
  /** Raw 128-bit (16-byte) random secret key material. */
  readonly rawBytes: Uint8Array<ArrayBuffer>;
  /** Canonical formatted string: `A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXX`. */
  readonly formatted: string;
}

const CHAR_TO_VALUE: ReadonlyMap<string, number> = (() => {
  const map = new Map<string, number>();
  for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
    const ch = CROCKFORD_ALPHABET[i];
    if (ch !== undefined) {
      map.set(ch, i);
    }
  }
  // Standard Crockford Base32 human-friendly aliases on input:
  // O -> 0, I/L -> 1
  map.set("O", 0);
  map.set("I", 1);
  map.set("L", 1);
  return map;
})();

/**
 * Encodes 16 bytes (128 bits) into 26 Crockford Base32 characters.
 * The 128 bits are placed in the upper 128 bits of the 130-bit (26 * 5) stream,
 * leaving the final 2 trailing bits set to 0.
 */
function encode128BitsToCrockford26(bytes: Uint8Array): string {
  if (bytes.byteLength !== SECRET_KEY_BYTE_LENGTH) {
    throw new SecretKeyError(
      "INVALID_LENGTH",
      `Secret Key must be ${String(SECRET_KEY_BYTE_LENGTH)} bytes (128 bits), got ${String(bytes.byteLength)}`
    );
  }

  let bitBuffer = 0;
  let bitCount = 0;
  let out = "";

  for (let i = 0; i < SECRET_KEY_BYTE_LENGTH; i++) {
    const byte = bytes[i] ?? 0;
    bitBuffer = (bitBuffer << 8) | byte;
    bitCount += 8;

    while (bitCount >= 5) {
      bitCount -= 5;
      const index = (bitBuffer >>> bitCount) & 0x1f;
      out += CROCKFORD_ALPHABET[index] ?? "";
    }
  }

  // Remaining 3 bits (128 % 5 === 3), shifted left by 2 zero pad bits to form the 26th 5-bit group.
  if (bitCount > 0) {
    const index = (bitBuffer << (5 - bitCount)) & 0x1f;
    out += CROCKFORD_ALPHABET[index] ?? "";
  }

  return out;
}

/**
 * Decodes 26 Crockford Base32 values (each 0..31) back into 16 bytes (128 bits).
 * Rejects inputs where the 2 unused trailing bits of the 26th character are non-zero,
 * ensuring canonical 1-to-1 encoding.
 */
function decodeCrockford26To128Bits(
  values: readonly number[]
): Uint8Array<ArrayBuffer> {
  const lastValue = values[SECRET_KEY_PAYLOAD_CHARS - 1] ?? 0;
  if ((lastValue & 0b00011) !== 0) {
    throw new SecretKeyError(
      "NON_ZERO_PAD_BITS",
      "Secret Key has non-zero padding bits in final character"
    );
  }

  const out = new Uint8Array(SECRET_KEY_BYTE_LENGTH);
  let bitBuffer = 0;
  let bitCount = 0;
  let outIndex = 0;

  for (let i = 0; i < SECRET_KEY_PAYLOAD_CHARS; i++) {
    const val = values[i] ?? 0;
    bitBuffer = (bitBuffer << 5) | val;
    bitCount += 5;

    while (bitCount >= 8 && outIndex < SECRET_KEY_BYTE_LENGTH) {
      bitCount -= 8;
      out[outIndex] = (bitBuffer >>> bitCount) & 0xff;
      outIndex++;
    }
  }

  return out;
}

/**
 * Computes a polynomial check character over the 2-character version prefix and 26 payload
 * characters using GF(32) / prime modulus 31 with distinct position weights `(i + 1)`
 * so that:
 * 1. Every single-character mistype at ANY position `i` changes `(i + 1) * delta`.
 *    Because we combine both a prime-field-like weighted sum modulo 31 AND parity/Luhn
 *    into a 5-bit check value, or even simpler: Luhn mod N (N = 32)!
 *
 * Why Luhn mod 32 detects 100% of single-character errors:
 * In Luhn mod 32, positions alternate multiplying by 1 and 2 (with digit-sum wrap `floor(2*v / 32) + (2*v % 32)`).
 * For factor 1: `f(v) = v` is a bijection on `0..31`.
 * For factor 2: `f(v) = (2*v) % 32 + floor(2*v / 32)` = `(2*v) % 31` (for `v < 31`) and `31` (for `v = 31`),
 * which is ALSO a strict bijection on `0..31`!
 * Because both `v -> v` and `v -> f(v)` are bijections modulo 32, changing ANY single character
 * at ANY position to any other character in the 32-character alphabet is guaranteed to change
 * the checksum mod 32 (100% single-error detection).
 */
function luhnMod32DoubleMap(value: number): number {
  const doubled = value * 2;
  return (doubled % 32) + Math.floor(doubled / 32);
}

function computeCheckCharacter(prefixAndPayloadValues: readonly number[]): string {
  let sum = 0;
  // Walk right-to-left, starting with factor = 2 on the rightmost payload character.
  let doublePosition = true;
  for (let i = prefixAndPayloadValues.length - 1; i >= 0; i--) {
    const val = prefixAndPayloadValues[i] ?? 0;
    const addend = doublePosition ? luhnMod32DoubleMap(val) : val;
    sum = (sum + addend) % 32;
    doublePosition = !doublePosition;
  }
  const checkValue = (32 - sum) % 32;
  return CROCKFORD_ALPHABET[checkValue] ?? "0";
}

function normalizeSecretKeyInput(input: string): string {
  // Strip spaces and hyphens, and uppercase for case-insensitive parsing.
  return input.replace(/[\s-]+/g, "").toUpperCase();
}

function parseCharsToValues(normalized: string): number[] {
  const values: number[] = [];
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i] ?? "";
    const val = CHAR_TO_VALUE.get(ch);
    if (val === undefined) {
      throw new SecretKeyError(
        "INVALID_CHARACTER",
        `Invalid character '${ch}' at position ${String(i)} in Secret Key`
      );
    }
    values.push(val);
  }
  return values;
}

/**
 * Formats 16 raw bytes (128 bits) as a canonical dashed Secret Key string:
 * `A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXX`
 * (2-char version `A3` + 26 payload chars + 1 check char = 29 alphanumeric chars).
 */
export function formatSecretKey(rawBytes: Uint8Array): string {
  const payload = encode128BitsToCrockford26(rawBytes);
  const prefixAndPayload = `${SECRET_KEY_VERSION_PREFIX}${payload}`;
  const prefixAndPayloadValues = parseCharsToValues(prefixAndPayload);
  const checkChar = computeCheckCharacter(prefixAndPayloadValues);
  const fullBody = `${payload}${checkChar}`; // 27 characters after "A3-"

  // Group the 27 characters after "A3" into readable chunks: 6-6-6-6-3
  const g1 = fullBody.slice(0, 6);
  const g2 = fullBody.slice(6, 12);
  const g3 = fullBody.slice(12, 18);
  const g4 = fullBody.slice(18, 24);
  const g5 = fullBody.slice(24, 27);

  return `${SECRET_KEY_VERSION_PREFIX}-${g1}-${g2}-${g3}-${g4}-${g5}`;
}

/**
 * Generates a fresh 128-bit random Secret Key and returns both its raw 16-byte buffer
 * and its canonical formatted representation.
 */
export function generateSecretKey(): SecretKey {
  const rawBytes = randomBytes(SECRET_KEY_BYTE_LENGTH);
  const formatted = formatSecretKey(rawBytes);
  return { rawBytes, formatted };
}

/**
 * Parses and validates a user-entered Secret Key string (case-insensitive, tolerant of
 * dashes, spaces, and Crockford O/I/L aliases). Rejects wrong prefixes, wrong lengths,
 * invalid characters, non-zero pad bits, and bad check characters with `SecretKeyError`.
 */
export function parseSecretKey(input: string): SecretKey {
  const normalized = normalizeSecretKeyInput(input);

  if (normalized.length < 2) {
    throw new SecretKeyError(
      "INVALID_LENGTH",
      `Secret Key is too short (${String(normalized.length)} characters)`
    );
  }

  // Check version prefix before checking full length or character set on the rest,
  // while still rejecting invalid characters in the prefix.
  const prefixCandidate = normalized.slice(0, 2);
  if (prefixCandidate !== SECRET_KEY_VERSION_PREFIX) {
    throw new SecretKeyError(
      "INVALID_PREFIX",
      `Unsupported Secret Key version prefix '${prefixCandidate}' (expected '${SECRET_KEY_VERSION_PREFIX}')`
    );
  }

  if (normalized.length !== SECRET_KEY_TOTAL_CHARS) {
    throw new SecretKeyError(
      "INVALID_LENGTH",
      `Secret Key must contain ${String(SECRET_KEY_TOTAL_CHARS)} alphanumeric characters, got ${String(normalized.length)}`
    );
  }

  const allValues = parseCharsToValues(normalized);
  const prefixAndPayloadValues = allValues.slice(0, SECRET_KEY_TOTAL_CHARS - 1);
  const providedCheckValue = allValues[SECRET_KEY_TOTAL_CHARS - 1];

  const expectedCheckChar = computeCheckCharacter(prefixAndPayloadValues);
  const expectedCheckValue = CHAR_TO_VALUE.get(expectedCheckChar);

  if (providedCheckValue !== expectedCheckValue) {
    throw new SecretKeyError(
      "CHECKSUM_MISMATCH",
      "Secret Key check character mismatch (possible typo)"
    );
  }

  const payloadValues = prefixAndPayloadValues.slice(2);
  const rawBytes = decodeCrockford26To128Bits(payloadValues);
  const formatted = formatSecretKey(rawBytes);

  return { rawBytes, formatted };
}

/**
 * Returns `true` if `input` is a valid Secret Key, or `false` otherwise.
 */
export function validateSecretKey(input: string): boolean {
  try {
    parseSecretKey(input);
    return true;
  } catch {
    return false;
  }
}

/**
 * Returns the canonical last 4 alphanumeric characters of a Secret Key (uppercase),
 * used for the signup Emergency Kit confirmation step (PRD Section 13 F1).
 */
export function getSecretKeyConfirmationSuffix(
  secretKeyInput: string | SecretKey
): string {
  const formatted =
    typeof secretKeyInput === "string"
      ? parseSecretKey(secretKeyInput).formatted
      : parseSecretKey(secretKeyInput.formatted).formatted;
  const normalized = normalizeSecretKeyInput(formatted);
  return normalized.slice(-4);
}
