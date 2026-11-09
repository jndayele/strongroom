export { buildAad } from "./aad.ts";
export {
  AeadDecryptionError,
  aeadDecrypt,
  aeadEncrypt,
} from "./aead.ts";
export {
  ALGORITHM_ID_AES_256_GCM,
  type DecodedEnvelope,
  decodeEnvelope,
  encodeEnvelope,
  ENVELOPE_HEADER_BYTE_LENGTH,
  ENVELOPE_VERSION_V1,
  EnvelopeError,
  type EnvelopeErrorCode,
  GCM_TAG_BYTE_LENGTH,
  LENGTH_PREFIX_BYTES,
  MAX_ENVELOPE_BYTE_LENGTH,
  MAX_PLAINTEXT_BYTE_LENGTH,
  NONCE_BYTE_LENGTH,
  PADDING_BUCKET_BYTES,
  padPlaintext,
  unpadPlaintext,
} from "./envelope.ts";
export {
  hkdfDeriveAesGcmKey,
  hkdfDeriveBytes,
  hkdfSha256Raw,
  KDF_LABEL_PRF_KEK_V1,
  KDF_LABEL_PW_INPUT_V1,
  KDF_LABEL_VAULT_KEK_V1,
  KDF_LABELS,
  type KdfLabel,
} from "./kdf.ts";
export {
  generateAndWrapKey,
  generateAndWrapVaultKeys,
  generateItemKey,
  generateKey,
  generateVaultKey,
  type GeneratedVaultKeyPair,
  type GeneratedWrappedKey,
  importNonExtractableAesGcmKey,
  KEY_BYTE_LENGTH,
  unwrapKey,
  wrapKey,
} from "./keys.ts";
export { randomBytes, randomInt } from "./random.ts";
export {
  formatSecretKey,
  generateSecretKey,
  getSecretKeyConfirmationSuffix,
  parseSecretKey,
  SECRET_KEY_BYTE_LENGTH,
  SECRET_KEY_PAYLOAD_CHARS,
  SECRET_KEY_TOTAL_CHARS,
  SECRET_KEY_VERSION_PREFIX,
  type SecretKey,
  SecretKeyError,
  type SecretKeyErrorCode,
  validateSecretKey,
} from "./secretKey.ts";
export { zeroize } from "./wipe.ts";
