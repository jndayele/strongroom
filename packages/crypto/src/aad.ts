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

function validateVersionUint32(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_UINT32) {
    throw new RangeError(
      `buildAad: ${name} must be an integer in [1, 2^32 - 1], got ${String(value)}`
    );
  }
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
  validateVersionUint32("keyVersion", keyVersion);
  validateVersionUint32("schemaVersion", schemaVersion);

  // Total length:
  // 4 + userBytes.length + 4 + itemBytes.length + (4 + 4) + (4 + 4)
  const totalLength = 4 + userBytes.byteLength + 4 + itemBytes.byteLength + 16;
  const out = new Uint8Array(totalLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);

  let offset = 0;

  // Field 1: userId (4-byte big-endian length + raw bytes)
  view.setUint32(offset, userBytes.byteLength, false);
  offset += 4;
  out.set(userBytes, offset);
  offset += userBytes.byteLength;

  // Field 2: itemId (4-byte big-endian length + raw bytes)
  view.setUint32(offset, itemBytes.byteLength, false);
  offset += 4;
  out.set(itemBytes, offset);
  offset += itemBytes.byteLength;

  // Field 3: keyVersion (4-byte big-endian length = 4, followed by 4-byte big-endian uint32)
  view.setUint32(offset, 4, false);
  offset += 4;
  view.setUint32(offset, keyVersion, false);
  offset += 4;

  // Field 4: schemaVersion (4-byte big-endian length = 4, followed by 4-byte big-endian uint32)
  view.setUint32(offset, 4, false);
  offset += 4;
  view.setUint32(offset, schemaVersion, false);

  return out;
}
