// Zero-out a byte buffer in place (best-effort).
//
// IMPORTANT LIMITATION:
// JavaScript and V8 do not guarantee that sensitive material is permanently erased
// from physical RAM. The JS engine may have copied data during garbage collection
// compaction, JIT optimization, or string interning before or after this call.
// However, explicitly overwriting Uint8Array / ArrayBuffer views immediately after
// use minimizes the window during which raw key bytes or plaintext remain in live
// heap objects, and prevents accidental reuse.

/**
 * Overwrites every byte of the given Uint8Array or ArrayBuffer with zeros.
 */
export function zeroize(buffer: Uint8Array | ArrayBuffer): void {
  if (buffer instanceof Uint8Array) {
    buffer.fill(0);
    return;
  }
  new Uint8Array(buffer).fill(0);
}
