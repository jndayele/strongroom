import { AuthClientError, type AuthClientErrorCode } from "./errors.ts";

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64URL_LOOKUP: ReadonlyMap<string, number> = (() => {
  const map = new Map<string, number>();
  for (let i = 0; i < BASE64URL_ALPHABET.length; i++) {
    const ch = BASE64URL_ALPHABET[i];
    if (ch !== undefined) {
      map.set(ch, i);
    }
  }
  return map;
})();

const textEncoder = new TextEncoder();

/**
 * Encodes raw bytes as unpadded URL-safe Base64 (`RFC 4648 §5`, no `=` padding).
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;

  while (i + 2 < bytes.byteLength) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;

    out +=
      (BASE64URL_ALPHABET[(triple >>> 18) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[(triple >>> 12) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[(triple >>> 6) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[triple & 0x3f] ?? "");
    i += 3;
  }

  const remaining = bytes.byteLength - i;
  if (remaining === 1) {
    const b0 = bytes[i] ?? 0;
    out +=
      (BASE64URL_ALPHABET[(b0 >>> 2) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[(b0 << 4) & 0x3f] ?? "");
  } else if (remaining === 2) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    out +=
      (BASE64URL_ALPHABET[(b0 >>> 2) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[((b0 << 4) | (b1 >>> 4)) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[(b1 << 2) & 0x3f] ?? "");
  }

  return out;
}

/**
 * Strictly decodes an unpadded URL-safe Base64 string into bytes.
 * Rejects empty strings, padding (`=`), invalid alphabet characters, non-canonical
 * trailing bits, and unexpected byte lengths.
 */
export function base64UrlToBytes(
  input: string,
  errorCode: AuthClientErrorCode = "INVALID_INPUT",
  expectedByteLength?: number
): Uint8Array<ArrayBuffer> {
  if (typeof input !== "string" || input.length === 0) {
    throw new AuthClientError(errorCode, "Invalid base64url string");
  }
  const rem = input.length % 4;
  if (rem === 1) {
    throw new AuthClientError(errorCode, "Invalid base64url length");
  }

  const sextets: number[] = [];
  for (let i = 0; i < input.length; i++) {
    const ch = input[i] ?? "";
    const val = BASE64URL_LOOKUP.get(ch);
    if (val === undefined) {
      throw new AuthClientError(errorCode, "Invalid base64url character");
    }
    sextets.push(val);
  }

  // Enforce canonical zeroed unused trailing bits per RFC 4648 §3.5.
  if (rem === 2) {
    const last = sextets[sextets.length - 1] ?? 0;
    if ((last & 0x0f) !== 0) {
      throw new AuthClientError(errorCode, "Non-canonical base64url padding");
    }
  } else if (rem === 3) {
    const last = sextets[sextets.length - 1] ?? 0;
    if ((last & 0x03) !== 0) {
      throw new AuthClientError(errorCode, "Non-canonical base64url padding");
    }
  }

  const outLength = Math.floor((input.length * 3) / 4);
  if (expectedByteLength !== undefined && outLength !== expectedByteLength) {
    throw new AuthClientError(errorCode, "Unexpected decoded byte length");
  }

  const out = new Uint8Array(outLength);
  let inIdx = 0;
  let outIdx = 0;

  while (inIdx + 3 < sextets.length) {
    const s0 = sextets[inIdx] ?? 0;
    const s1 = sextets[inIdx + 1] ?? 0;
    const s2 = sextets[inIdx + 2] ?? 0;
    const s3 = sextets[inIdx + 3] ?? 0;
    const triple = (s0 << 18) | (s1 << 12) | (s2 << 6) | s3;

    out[outIdx] = (triple >>> 16) & 0xff;
    out[outIdx + 1] = (triple >>> 8) & 0xff;
    out[outIdx + 2] = triple & 0xff;
    inIdx += 4;
    outIdx += 3;
  }

  if (rem === 2) {
    const s0 = sextets[inIdx] ?? 0;
    const s1 = sextets[inIdx + 1] ?? 0;
    out[outIdx] = ((s0 << 2) | (s1 >>> 4)) & 0xff;
  } else if (rem === 3) {
    const s0 = sextets[inIdx] ?? 0;
    const s1 = sextets[inIdx + 1] ?? 0;
    const s2 = sextets[inIdx + 2] ?? 0;
    out[outIdx] = ((s0 << 2) | (s1 >>> 4)) & 0xff;
    out[outIdx + 1] = ((s1 << 4) | (s2 >>> 2)) & 0xff;
  }

  return out;
}

/**
 * Constant-time string equality check over UTF-8 encoded bytes.
 */
export function constantTimeEqualStrings(a: string, b: string): boolean {
  const aBytes = textEncoder.encode(a);
  const bBytes = textEncoder.encode(b);
  if (aBytes.byteLength !== bBytes.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < aBytes.byteLength; i++) {
    diff |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
  }
  return diff === 0;
}
