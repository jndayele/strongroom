import { CryptoArgumentError, WebCryptoUnavailableError } from './errors.ts';

/**
 * Returns the platform WebCrypto instance, throwing a uniform error if missing.
 */
export function getWebCrypto(): Crypto {
  if (
    typeof globalThis === 'undefined' ||
    typeof globalThis.crypto === 'undefined' ||
    typeof globalThis.crypto.getRandomValues !== 'function' ||
    typeof globalThis.crypto.subtle === 'undefined'
  ) {
    throw new WebCryptoUnavailableError();
  }
  return globalThis.crypto;
}

/**
 * Copies a Uint8Array into a fresh, tightly-sized ArrayBuffer suitable for
 * WebCrypto BufferSource parameters under TypeScript strict mode.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (!(bytes instanceof Uint8Array)) {
    throw new CryptoArgumentError();
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Best-effort in-place zeroing of a typed array view or ArrayBuffer.
 *
 * JavaScript runtimes do not expose pinned memory or forbid GC relocation,
 * so this is best-effort hygiene for mutable byte buffers holding keys,
 * plaintexts, or intermediate material (PRD Section 8).
 */
export function wipeBuffer(buffer: ArrayBufferView | ArrayBuffer): void {
  if (buffer instanceof ArrayBuffer) {
    new Uint8Array(buffer).fill(0);
    return;
  }
  if (ArrayBuffer.isView(buffer)) {
    new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).fill(0);
    return;
  }
  throw new CryptoArgumentError();
}

/**
 * Best-effort wipe helper for multiple buffers (ignores null/undefined entries
 * for convenient use in `finally` blocks).
 */
export function wipeBuffers(
  ...buffers: ReadonlyArray<ArrayBufferView | ArrayBuffer | null | undefined>
): void {
  for (const buf of buffers) {
    if (buf !== null && buf !== undefined) {
      wipeBuffer(buf);
    }
  }
}

/**
 * Constant-time byte array equality check.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    throw new CryptoArgumentError();
  }
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
