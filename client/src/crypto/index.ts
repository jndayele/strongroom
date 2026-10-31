/**
 * Strongroom Client Cryptography Module (PRD Sections 5.1 – 5.3).
 *
 * Implemented exclusively using the browser's built-in WebCrypto API with
 * zero external dependencies.
 */

export {
  DECRYPTION_ERROR_MESSAGE,
  INVALID_CRYPTO_ARGUMENT_MESSAGE,
  INVALID_SECRET_KEY_MESSAGE,
  WEBCRYPTO_UNAVAILABLE_MESSAGE,
  CryptoArgumentError,
  DecryptionError,
  InvalidSecretKeyError,
  WebCryptoUnavailableError,
} from './errors.ts';

export {
  constantTimeEqual,
  getWebCrypto,
  toArrayBuffer,
  wipeBuffer,
  wipeBuffers,
} from './memory.ts';

export { secureRandom } from './random.ts';

export {
  deriveKek,
  derivePasswordInput,
} from './hkdf.ts';

export {
  MAX_SECRET_KEY_INPUT_LENGTH,
  SECRET_KEY_BASE32_ALPHABET,
  SECRET_KEY_BASE32_CHARS,
  SECRET_KEY_BYTES,
  SECRET_KEY_CRC7_POLY,
  SECRET_KEY_CRC7_SEED,
  SECRET_KEY_GROUP_LENGTHS,
  SECRET_KEY_PREFIX,
  formatSecretKey,
  generateSecretKey,
  parseSecretKey,
} from './secretKey.ts';

export {
  AAD_PURPOSES,
  MAX_AAD_ID_BYTES,
  type AadParams,
  type AadPurpose,
  type BaseAadParams,
  type DataAadParams,
  type DataAadPurpose,
  type ItemAadContext,
  type ItemAadPurpose,
  type ItemKeyAadParams,
  type ItemKeyAadPurpose,
  type ItemPurposeAadParams,
  type KeyWrapAadParams,
  type KeyWrapAadPurpose,
  type VaultKeyAadPurpose,
  type VaultKeyMasterAadParams,
  type VaultKeyMasterAadPurpose,
  type VaultKeyPrfAadParams,
  type VaultKeyWrapAadParams,
  encodeAad,
} from './aad.ts';

export {
  MAX_PLAINTEXT_BYTES,
  PADDING_BUCKET_BYTES,
  PADDING_LENGTH_PREFIX_BYTES,
  maxPaddedBytesForOverhead,
  padToBucket,
  unpadFromBucket,
} from './padding.ts';

export {
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BITS,
  AES_GCM_TAG_BYTES,
  ENVELOPE_HEADER_BYTES,
  ENVELOPE_OVERHEAD_BYTES,
  ENVELOPE_VERSION_V1,
  type DecodedEnvelope,
  decodeEnvelope,
} from './envelope.ts';

export {
  AES_256_KEY_BITS,
  AES_256_KEY_BYTES,
  MAX_ENCRYPTED_ENVELOPE_BYTES,
  assertValidKeyUsages,
  decrypt,
  encrypt,
  isAes256GcmDataKey,
  isAes256GcmKey,
  isAes256GcmWrappingKey,
} from './aesGcm.ts';

export {
  WRAPPED_KEY_ENVELOPE_BYTES,
  createAndWrapVaultKey,
  rewrapKey,
  unwrapKey,
  wrapKey,
} from './keyWrap.ts';

export {
  type EncryptedVaultItem,
  type PlaintextVaultItem,
  type VaultKeyPair,
  decryptItem,
  decryptItemMetadata,
  decryptItemSecret,
  encryptItem,
} from './itemCrypto.ts';
