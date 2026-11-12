export { canonicalizeEmail, MAX_EMAIL_LENGTH } from "./email.ts";
export { AuthClientError, type AuthClientErrorCode } from "./errors.ts";
export {
  KDF_MAX_ITERATIONS,
  KDF_MAX_MEMORY_KIB,
  KDF_MAX_PARALLELISM,
  KDF_MIN_ITERATIONS,
  KDF_MIN_MEMORY_KIB,
  KDF_MIN_PARALLELISM,
  type KdfParams,
  validateKdfParams,
} from "./kdfParams.ts";
export {
  deriveKek,
  derivePwInput,
  encodeLengthPrefixedPair,
} from "./keys.ts";
export {
  type AuthClientConfig,
  type FetchFn,
  login,
  type LoginParams,
  type LoginResult,
  type OpaqueClientAdapter,
  signup,
  type SignupParams,
  type SignupResult,
} from "./opaqueClient.ts";
