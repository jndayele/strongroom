// HKDF-SHA-256 wrapper with explicit, constant domain-separation labels (PRD Sections 3 and 5.2).
//
// Security invariant:
// Callers must pass one of the exported `KdfLabel` constants (`KDF_LABELS`), never an arbitrary
// free-form string, so two different subsystems can never accidentally share derived key streams.

import { zeroize } from "./wipe.ts";

export const KDF_LABEL_PW_INPUT_V1 = "strongroom-pw-input-v1" as const;
export const KDF_LABEL_VAULT_KEK_V1 = "vault-kek-v1" as const;
export const KDF_LABEL_PRF_KEK_V1 = "strongroom-prf-kek-v1" as const;

export const KDF_LABELS = {
  PW_INPUT_V1: KDF_LABEL_PW_INPUT_V1,
  VAULT_KEK_V1: KDF_LABEL_VAULT_KEK_V1,
  PRF_KEK_V1: KDF_LABEL_PRF_KEK_V1,
} as const;

export type KdfLabel = (typeof KDF_LABELS)[keyof typeof KDF_LABELS];

const VALID_KDF_LABELS: ReadonlySet<string> = new Set<string>(
  Object.values(KDF_LABELS)
);

const textEncoder = new TextEncoder();

function assertValidKdfLabel(label: KdfLabel): Uint8Array<ArrayBuffer> {
  if (!VALID_KDF_LABELS.has(label)) {
    throw new TypeError(`Invalid HKDF domain-separation label: ${String(label)}`);
  }
  const encoded = textEncoder.encode(label);
  const out = new Uint8Array(encoded.byteLength);
  out.set(encoded);
  return out;
}

function toSafeByteCopy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

async function importHkdfBaseKey(ikm: Uint8Array): Promise<CryptoKey> {
  if (ikm.byteLength === 0) {
    throw new RangeError("HKDF input keying material (ikm) must not be empty");
  }
  const ikmCopy = toSafeByteCopy(ikm);
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      ikmCopy,
      "HKDF",
      false,
      ["deriveBits", "deriveKey"]
    );
  } finally {
    zeroize(ikmCopy);
  }
}

/**
 * Derives a non-extractable 256-bit AES-GCM `CryptoKey` using HKDF-SHA-256
 * with an explicit domain-separation label from `KDF_LABELS`.
 *
 * For example, deriving the Vault Key Encryption Key (PRD Section 5.2):
 * `const kek = await hkdfDeriveAesGcmKey(exportKey, secretKeyBytes, KDF_LABEL_VAULT_KEK_V1);`
 */
export async function hkdfDeriveAesGcmKey(
  ikm: Uint8Array,
  salt: Uint8Array,
  label: KdfLabel,
  usages: readonly KeyUsage[] = ["encrypt", "decrypt"]
): Promise<CryptoKey> {
  const infoBytes = assertValidKdfLabel(label);
  const saltBytes = toSafeByteCopy(salt);
  const baseKey = await importHkdfBaseKey(ikm);

  return await globalThis.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: infoBytes,
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false, // non-extractable
    [...usages]
  );
}

/**
 * Derives raw bytes using HKDF-SHA-256 with an explicit domain-separation label from `KDF_LABELS`.
 * Use only when raw bytes are required by a downstream protocol (such as `pw_input` for OPAQUE).
 * Callers must `zeroize()` the returned buffer as soon as it is consumed.
 */
export async function hkdfDeriveBytes(
  ikm: Uint8Array,
  salt: Uint8Array,
  label: KdfLabel,
  byteLength = 32
): Promise<Uint8Array<ArrayBuffer>> {
  const infoBytes = assertValidKdfLabel(label);
  return await hkdfSha256Raw(ikm, salt, infoBytes, byteLength);
}

/**
 * Low-level RFC 5869 HKDF-SHA-256 primitive backed by `crypto.subtle.deriveBits`.
 * Exported for RFC 5869 test-vector verification; application code must use
 * `hkdfDeriveAesGcmKey` or `hkdfDeriveBytes` with a constant `KdfLabel`.
 */
export async function hkdfSha256Raw(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  byteLength: number
): Promise<Uint8Array<ArrayBuffer>> {
  // RFC 5869 max output for SHA-256 is 255 * 32 = 8,160 bytes.
  if (!Number.isSafeInteger(byteLength) || byteLength <= 0 || byteLength > 255 * 32) {
    throw new RangeError(
      `HKDF-SHA-256 byteLength must be an integer in [1, 8160], got ${String(byteLength)}`
    );
  }

  const baseKey = await importHkdfBaseKey(ikm);
  const saltBytes = toSafeByteCopy(salt);
  const infoBytes = toSafeByteCopy(info);

  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBytes,
      info: infoBytes,
    },
    baseKey,
    byteLength * 8
  );

  return new Uint8Array(bits);
}
