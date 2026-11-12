import {
  hkdfDeriveAesGcmKey,
  hkdfDeriveBytes,
  KDF_LABEL_PW_INPUT_V1,
  KDF_LABEL_VAULT_KEK_V1,
  SECRET_KEY_BYTE_LENGTH,
  type SecretKey,
  zeroize,
} from "@strongroom/crypto";
import { bytesToBase64Url } from "./base64url.ts";
import { AuthClientError } from "./errors.ts";

const PW_INPUT_BYTE_LENGTH = 32 as const;
const textEncoder = new TextEncoder();

/**
 * Encodes two byte slices with 4-byte big-endian length prefixes:
 * `[4B len(first)][first][4B len(second)][second]`
 * so boundary shifts (e.g. `"ab" + "c"` vs `"a" + "bc"`) can never collide.
 */
export function encodeLengthPrefixedPair(
  first: Uint8Array,
  second: Uint8Array
): Uint8Array<ArrayBuffer> {
  const totalLength = 4 + first.byteLength + 4 + second.byteLength;
  const out = new Uint8Array(totalLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);

  let offset = 0;
  view.setUint32(offset, first.byteLength, false);
  offset += 4;
  out.set(first, offset);
  offset += first.byteLength;

  view.setUint32(offset, second.byteLength, false);
  offset += 4;
  out.set(second, offset);

  return out;
}

function extractSecretKeyBytes(secretKey: Uint8Array | SecretKey): Uint8Array {
  const raw = secretKey instanceof Uint8Array ? secretKey : secretKey.rawBytes;
  if (raw.byteLength !== SECRET_KEY_BYTE_LENGTH) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Secret Key must be 16 bytes (128 bits)"
    );
  }
  return raw;
}

/**
 * Derives the OPAQUE password input (`pw_input`) from the user's master password
 * and 16-byte Secret Key:
 * 1. NFKC-normalizes `masterPassword` and UTF-8 encodes it.
 * 2. Encodes `length_prefix(passwordBytes) || length_prefix(secretKeyBytes)`.
 * 3. Runs HKDF-SHA-256 with `KDF_LABEL_PW_INPUT_V1` (`"strongroom-pw-input-v1"`).
 * 4. Returns unpadded base64url for `@serenity-kit/opaque` and zeroes intermediate buffers.
 */
export async function derivePwInput(
  masterPassword: string,
  secretKey: Uint8Array | SecretKey
): Promise<string> {
  if (typeof masterPassword !== "string" || masterPassword.length === 0) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Master password must not be empty"
    );
  }

  const secretKeyBytes = extractSecretKeyBytes(secretKey);
  const normalizedPassword = masterPassword.normalize("NFKC");
  const passwordBytes = textEncoder.encode(normalizedPassword);
  const ikm = encodeLengthPrefixedPair(passwordBytes, secretKeyBytes);
  const emptySalt = new Uint8Array(0);
  let derivedBytes: Uint8Array<ArrayBuffer> | undefined;

  try {
    derivedBytes = await hkdfDeriveBytes(
      ikm,
      emptySalt,
      KDF_LABEL_PW_INPUT_V1,
      PW_INPUT_BYTE_LENGTH
    );
    return bytesToBase64Url(derivedBytes);
  } finally {
    zeroize(passwordBytes);
    zeroize(ikm);
    if (derivedBytes !== undefined) {
      zeroize(derivedBytes);
    }
  }
}

/**
 * Derives the non-extractable AES-256-GCM Vault Key Encryption Key (KEK):
 * `KEK = HKDF-SHA-256(ikm = exportKeyBytes, salt = secretKeyBytes, info = "vault-kek-v1")`.
 * Always zeroes `exportKeyBytes` afterwards.
 */
export async function deriveKek(
  exportKeyBytes: Uint8Array,
  secretKeyBytes: Uint8Array
): Promise<CryptoKey> {
  try {
    if (exportKeyBytes.byteLength === 0) {
      throw new AuthClientError(
        "INVALID_INPUT",
        "OPAQUE export key must not be empty"
      );
    }
    if (secretKeyBytes.byteLength !== SECRET_KEY_BYTE_LENGTH) {
      throw new AuthClientError(
        "INVALID_INPUT",
        "Secret Key must be 16 bytes (128 bits)"
      );
    }

    return await hkdfDeriveAesGcmKey(
      exportKeyBytes,
      secretKeyBytes,
      KDF_LABEL_VAULT_KEK_V1
    );
  } finally {
    zeroize(exportKeyBytes);
  }
}
