// Canonical length-prefixed Authenticated Associated Data (AAD) builder (PRD Section 5.3).
//
// WHY LENGTH-PREFIXED ENCODING INSTEAD OF PLAIN CONCATENATION:
// Plain concatenation (`userId || itemId || keyVersion || schemaVersion`) is ambiguous
// whenever variable-length fields are adjacent: for example,
//   userId = "abc", itemId = "def"
// and
//   userId = "ab",  itemId = "cdef"
// both produce the exact same concatenated byte stream `"abcdef"`.
// In cryptography this is known as a canonicalization / framing flaw: an attacker who can
// influence boundary placement between fields could forge a valid AAD collision across two
// distinct (userId, itemId) tuples.
//
// By prefixing every variable-length field with its exact byte length as a fixed-width
// 32-bit unsigned big-endian integer, and encoding integer version fields as fixed-width
// 32-bit unsigned big-endian integers (each also preceded by its 4-byte length = 4),
// the encoding becomes an injective (one-to-one) mapping: two AAD byte arrays are equal
// if and only if every input field (`userId`, `itemId`, `keyVersion`, `schemaVersion`) is
// byte-for-byte identical.

const MAX_IDENTIFIER_BYTES = 1024;
const MAX_UINT32 = 0xffff_ffff;
const textEncoder = new TextEncoder();

const KEY_WRAP_AAD_DOMAIN_PREFIX = textEncoder.encode(
  "strongroom-key-wrap-v1"
);

export type KeyWrapPurpose = "K_m" | "K_s" | "K_s_prf";

const VALID_KEY_WRAP_PURPOSES: ReadonlySet<string> = new Set<string>([
  "K_m",
  "K_s",
  "K_s_prf",
]);

function toIdentifierBytes(
  name: string,
  value: string | Uint8Array
): Uint8Array {
  const bytes =
    typeof value === "string" ? textEncoder.encode(value) : value;
  if (bytes.byteLength === 0) {
    throw new RangeError(`buildAad: ${name} must not be empty`);
  }
  if (bytes.byteLength > MAX_IDENTIFIER_BYTES) {
    throw new RangeError(
      `buildAad: ${name} byte length (${String(bytes.byteLength)}) exceeds maximum (${String(MAX_IDENTIFIER_BYTES)})`
    );
  }
  return bytes;
}

function validateVersionUint32(fnName: string, name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_UINT32) {
    throw new RangeError(
      `${fnName}: ${name} must be an integer in [1, 2^32 - 1], got ${String(value)}`
    );
  }
}

function uint32BigEndianBytes(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value, false);
  return buf;
}

/**
 * Shared length-prefixed encoder: prepends an optional domain-separation prefix
 * and encodes each field as `[4-byte big-endian length][raw bytes]`.
 */
function encodeLengthPrefixedFields(
  fields: readonly Uint8Array[],
  domainPrefix?: Uint8Array
): Uint8Array<ArrayBuffer> {
  const prefixLength = domainPrefix ? domainPrefix.byteLength : 0;
  let totalLength = prefixLength;
  for (const field of fields) {
    totalLength += 4 + field.byteLength;
  }

  const out = new Uint8Array(totalLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  let offset = 0;

  if (domainPrefix) {
    out.set(domainPrefix, offset);
    offset += domainPrefix.byteLength;
  }

  for (const field of fields) {
    view.setUint32(offset, field.byteLength, false);
    offset += 4;
    out.set(field, offset);
    offset += field.byteLength;
  }

  return out;
}

/**
 * Builds canonical, unambiguous length-prefixed AAD bytes binding a ciphertext to:
 * - `userId` (non-empty string or bytes)
 * - `itemId` (non-empty string or bytes)
 * - `keyVersion` (positive 32-bit integer)
 * - `schemaVersion` (positive 32-bit integer)
 *
 * Binary layout:
 *   `[4B len(userId)][userId][4B len(itemId)][itemId][4B len=4][4B keyVersion][4B len=4][4B schemaVersion]`
 * All integers and lengths are 32-bit unsigned big-endian.
 */
export function buildAad(
  userId: string | Uint8Array,
  itemId: string | Uint8Array,
  keyVersion: number,
  schemaVersion: number
): Uint8Array<ArrayBuffer> {
  const userBytes = toIdentifierBytes("userId", userId);
  const itemBytes = toIdentifierBytes("itemId", itemId);
  validateVersionUint32("buildAad", "keyVersion", keyVersion);
  validateVersionUint32("buildAad", "schemaVersion", schemaVersion);

  return encodeLengthPrefixedFields([
    userBytes,
    itemBytes,
    uint32BigEndianBytes(keyVersion),
    uint32BigEndianBytes(schemaVersion),
  ]);
}

/**
 * Builds canonical, domain-separated length-prefixed AAD bytes for vault key wrapping
 * (`K_m`, `K_s`, or `K_s_prf`), bound to `keyVersion` and `schemaVersion`.
 *
 * Uses a fixed domain-separation prefix (`"strongroom-key-wrap-v1"`, starting with ASCII
 * bytes `0x73 0x74`, whereas item AAD always starts with `0x00 0x00` from `len <= 1024`)
 * followed by length-prefixed `(purpose, keyVersion, schemaVersion)` so it can never
 * collide with `buildAad`.
 */
export function buildKeyWrapAad(
  purpose: KeyWrapPurpose,
  keyVersion: number,
  schemaVersion: number
): Uint8Array<ArrayBuffer> {
  if (!VALID_KEY_WRAP_PURPOSES.has(purpose)) {
    throw new RangeError(
      `buildKeyWrapAad: invalid purpose '${String(purpose)}'`
    );
  }
  validateVersionUint32("buildKeyWrapAad", "keyVersion", keyVersion);
  validateVersionUint32("buildKeyWrapAad", "schemaVersion", schemaVersion);

  const purposeBytes = textEncoder.encode(purpose);
  return encodeLengthPrefixedFields(
    [
      purposeBytes,
      uint32BigEndianBytes(keyVersion),
      uint32BigEndianBytes(schemaVersion),
    ],
    KEY_WRAP_AAD_DOMAIN_PREFIX
  );
}
