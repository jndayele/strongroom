import * as opaque from "@serenity-kit/opaque";
import {
  buildKeyWrapAad,
  generateAndWrapVaultKeys,
  generateSecretKey,
  parseSecretKey,
  SECRET_KEY_BYTE_LENGTH,
  type SecretKey,
  zeroize,
} from "@strongroom/crypto";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  constantTimeEqualStrings,
} from "./base64url.ts";
import { canonicalizeEmail } from "./email.ts";
import { AuthClientError } from "./errors.ts";
import { type KdfParams, validateKdfParams } from "./kdfParams.ts";
import { deriveKek, derivePwInput } from "./keys.ts";

const VAULT_KEY_VERSION_INITIAL = 1 as const;
const VAULT_SCHEMA_VERSION_INITIAL = 1 as const;

const SERVER_PUBLIC_KEY_BYTE_LENGTH = 32 as const;
const OPAQUE_EXPORT_KEY_BYTE_LENGTH = 64 as const;
const OPAQUE_REG_RESPONSE_BYTE_LENGTH = 64 as const;
const OPAQUE_CRED_RESPONSE_BYTE_LENGTH = 320 as const;
const LOGIN_ID_BYTE_LENGTH = 32 as const;

export type FetchFn = (
  input: string | URL | Request,
  init?: RequestInit
) => Promise<Response>;

export interface OpaqueClientAdapter {
  readonly ready: Promise<void>;
  readonly client: {
    readonly startRegistration: typeof opaque.client.startRegistration;
    readonly finishRegistration: typeof opaque.client.finishRegistration;
    readonly startLogin: typeof opaque.client.startLogin;
    readonly finishLogin: typeof opaque.client.finishLogin;
  };
}

export interface AuthClientConfig {
  readonly baseUrl: string;
  readonly expectedServerPublicKey: string;
  readonly fetch?: FetchFn;
  readonly opaqueAdapter?: OpaqueClientAdapter;
}

export interface SignupParams {
  readonly email: string;
  readonly masterPassword: string;
}

export interface SignupResult {
  readonly canonicalEmail: string;
  readonly secretKey: SecretKey;
  readonly kek: CryptoKey;
  readonly km: CryptoKey;
  readonly ks: CryptoKey;
  readonly wrappedKm: Uint8Array<ArrayBuffer>;
  readonly wrappedKsMaster: Uint8Array<ArrayBuffer>;
  readonly keyVersion: number;
  readonly schemaVersion: number;
}

export interface LoginParams {
  readonly email: string;
  readonly masterPassword: string;
  readonly secretKey: SecretKey | Uint8Array | string;
  readonly deviceId?: string;
}

export interface LoginResult {
  readonly canonicalEmail: string;
  readonly kek: CryptoKey;
  readonly status: "mfa_required";
}

interface ValidatedConfig {
  readonly baseUrl: string;
  readonly expectedServerPublicKey: string;
  readonly fetchImpl: FetchFn;
  readonly opaqueImpl: OpaqueClientAdapter;
}

interface SignupStartServerResponse {
  readonly registrationResponse: string;
  readonly kdfParams: KdfParams;
}

interface LoginStartServerResponse {
  readonly loginId: string;
  readonly credentialResponse: string;
  readonly kdfParams: KdfParams;
}

function validateConfig(config: AuthClientConfig): ValidatedConfig {
  if (typeof config.baseUrl !== "string" || config.baseUrl.trim().length === 0) {
    throw new AuthClientError("INVALID_INPUT", "API baseUrl must not be empty");
  }
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(config.baseUrl);
  } catch {
    throw new AuthClientError("INVALID_INPUT", "API baseUrl is not a valid URL");
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new AuthClientError(
      "INVALID_INPUT",
      "API baseUrl must use http or https"
    );
  }

  // Validate expectedServerPublicKey is a 32-byte base64url Ristretto255 public key.
  base64UrlToBytes(
    config.expectedServerPublicKey,
    "INVALID_INPUT",
    SERVER_PUBLIC_KEY_BYTE_LENGTH
  );

  const fetchImpl = config.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new AuthClientError("NETWORK", "No fetch implementation available");
  }

  const opaqueImpl = config.opaqueAdapter ?? opaque;
  const normalizedBaseUrl = config.baseUrl.replace(/\/+$/, "");
  return {
    baseUrl: normalizedBaseUrl,
    expectedServerPublicKey: config.expectedServerPublicKey,
    fetchImpl,
    opaqueImpl,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertExactKeys(
  obj: Record<string, unknown>,
  expectedKeys: readonly string[]
): void {
  const actualKeys = Object.keys(obj);
  if (actualKeys.length !== expectedKeys.length) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server response contained unexpected fields"
    );
  }
  for (const key of expectedKeys) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) {
      throw new AuthClientError(
        "UNTRUSTED_SERVER",
        "Server response missing required field"
      );
    }
  }
}

function expectBase64UrlField(
  obj: Record<string, unknown>,
  key: string,
  expectedByteLength: number
): string {
  const value = obj[key];
  if (typeof value !== "string") {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server response contained invalid field type"
    );
  }
  base64UrlToBytes(value, "UNTRUSTED_SERVER", expectedByteLength);
  return value;
}

function parseSignupStartResponse(json: unknown): SignupStartServerResponse {
  if (!isPlainObject(json)) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned non-object response"
    );
  }
  assertExactKeys(json, ["registration_response", "kdf_params"]);
  const registrationResponse = expectBase64UrlField(
    json,
    "registration_response",
    OPAQUE_REG_RESPONSE_BYTE_LENGTH
  );
  const kdfParams = validateKdfParams(json["kdf_params"]);
  return { registrationResponse, kdfParams };
}

function parseSignupFinishResponse(json: unknown): void {
  if (!isPlainObject(json)) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned non-object response"
    );
  }
  assertExactKeys(json, ["status"]);
  if (json["status"] !== "ok") {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned unexpected signup status"
    );
  }
}

function parseLoginStartResponse(json: unknown): LoginStartServerResponse {
  if (!isPlainObject(json)) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned non-object response"
    );
  }
  assertExactKeys(json, ["login_id", "credential_response", "kdf_params"]);
  const loginId = expectBase64UrlField(json, "login_id", LOGIN_ID_BYTE_LENGTH);
  const credentialResponse = expectBase64UrlField(
    json,
    "credential_response",
    OPAQUE_CRED_RESPONSE_BYTE_LENGTH
  );
  const kdfParams = validateKdfParams(json["kdf_params"]);
  return { loginId, credentialResponse, kdfParams };
}

function parseLoginFinishResponse(json: unknown): "mfa_required" {
  if (!isPlainObject(json)) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned non-object response"
    );
  }
  assertExactKeys(json, ["status"]);
  if (json["status"] !== "mfa_required") {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned unexpected login status"
    );
  }
  return "mfa_required";
}

async function postJson(
  fetchImpl: FetchFn,
  url: string,
  body: Record<string, string>,
  mode: "signup" | "login",
  credentials: RequestCredentials = "omit"
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials,
      body: JSON.stringify(body),
    });
  } catch {
    throw new AuthClientError("NETWORK", "Authentication request failed");
  }

  if (!response.ok) {
    if (mode === "login" && (response.status === 401 || response.status === 400)) {
      throw new AuthClientError("AUTH_FAILED", "Authentication failed");
    }
    if (mode === "signup" && response.status === 400) {
      throw new AuthClientError("INVALID_INPUT", "Signup request was rejected");
    }
    throw new AuthClientError(
      "NETWORK",
      `Server returned HTTP ${String(response.status)}`
    );
  }

  try {
    return (await response.json()) as unknown;
  } catch {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned malformed JSON"
    );
  }
}

function buildKeyStretchingConfig(kdfParams: KdfParams): {
  "argon2id-custom": {
    memory: number;
    iterations: number;
    parallelism: number;
  };
} {
  return {
    "argon2id-custom": {
      memory: kdfParams.memory,
      iterations: kdfParams.iterations,
      parallelism: kdfParams.parallelism,
    },
  };
}

function verifyPinnedServerPublicKey(
  returnedKey: string,
  expectedKey: string
): void {
  if (!constantTimeEqualStrings(returnedKey, expectedKey)) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server static public key does not match pinned key"
    );
  }
}

function resolveLoginSecretKey(
  input: SecretKey | Uint8Array | string
): { bytes: Uint8Array; shouldZeroize: boolean } {
  if (typeof input === "string") {
    try {
      const parsed = parseSecretKey(input);
      return { bytes: parsed.rawBytes, shouldZeroize: true };
    } catch {
      throw new AuthClientError("INVALID_INPUT", "Invalid Secret Key format");
    }
  }
  if (input instanceof Uint8Array) {
    if (input.byteLength !== SECRET_KEY_BYTE_LENGTH) {
      throw new AuthClientError(
        "INVALID_INPUT",
        "Secret Key must be 16 bytes (128 bits)"
      );
    }
    return { bytes: input, shouldZeroize: false };
  }
  if (input.rawBytes.byteLength !== SECRET_KEY_BYTE_LENGTH) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Secret Key must be 16 bytes (128 bits)"
    );
  }
  return { bytes: input.rawBytes, shouldZeroize: false };
}

/**
 * Executes the client-side OPAQUE signup ceremony:
 * 1. Canonicalizes email and generates a fresh 128-bit Secret Key.
 * 2. Derives `pw_input` and starts OPAQUE registration.
 * 3. Validates server `kdf_params` BEFORE calling Argon2id WASM.
 * 4. Finishes OPAQUE registration with explicit `argon2id-custom` parameters.
 * 5. Verifies `serverStaticPublicKey` against `expectedServerPublicKey` BEFORE deriving KEK or sending finish.
 * 6. Derives KEK, generates & wraps `K_m` and `K_s` (`key_version = 1`), and finishes signup.
 */
export async function signup(
  params: SignupParams,
  config: AuthClientConfig
): Promise<SignupResult> {
  const validatedConfig = validateConfig(config);
  const canonicalEmail = canonicalizeEmail(params.email);

  if (
    typeof params.masterPassword !== "string" ||
    params.masterPassword.length === 0
  ) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Master password must not be empty"
    );
  }

  const { opaqueImpl } = validatedConfig;
  await opaqueImpl.ready;

  const secretKey = generateSecretKey();
  const pwInput = await derivePwInput(params.masterPassword, secretKey.rawBytes);
  const regStart = opaqueImpl.client.startRegistration({ password: pwInput });

  const startJson = await postJson(
    validatedConfig.fetchImpl,
    `${validatedConfig.baseUrl}/auth/signup/start`,
    {
      email: canonicalEmail,
      registration_request: regStart.registrationRequest,
    },
    "signup"
  );
  const { registrationResponse, kdfParams } =
    parseSignupStartResponse(startJson);

  let regFinish: opaque.client.FinishRegistrationResult;
  try {
    regFinish = opaqueImpl.client.finishRegistration({
      clientRegistrationState: regStart.clientRegistrationState,
      registrationResponse,
      password: pwInput,
      keyStretching: buildKeyStretchingConfig(kdfParams),
    });
  } catch {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned invalid OPAQUE registration response"
    );
  }

  // Must verify pinned server public key BEFORE deriving KEK or sending /signup/finish.
  verifyPinnedServerPublicKey(
    regFinish.serverStaticPublicKey,
    validatedConfig.expectedServerPublicKey
  );

  const exportKeyBytes = base64UrlToBytes(
    regFinish.exportKey,
    "UNTRUSTED_SERVER",
    OPAQUE_EXPORT_KEY_BYTE_LENGTH
  );
  const kek = await deriveKek(exportKeyBytes, secretKey.rawBytes);

  const kmAad = buildKeyWrapAad(
    "K_m",
    VAULT_KEY_VERSION_INITIAL,
    VAULT_SCHEMA_VERSION_INITIAL
  );
  const ksAad = buildKeyWrapAad(
    "K_s",
    VAULT_KEY_VERSION_INITIAL,
    VAULT_SCHEMA_VERSION_INITIAL
  );
  const vaultKeys = await generateAndWrapVaultKeys(kek, kmAad, ksAad);

  const finishJson = await postJson(
    validatedConfig.fetchImpl,
    `${validatedConfig.baseUrl}/auth/signup/finish`,
    {
      email: canonicalEmail,
      registration_record: regFinish.registrationRecord,
      wrapped_km: bytesToBase64Url(vaultKeys.wrappedKm),
      wrapped_ks_master: bytesToBase64Url(vaultKeys.wrappedKs),
    },
    "signup"
  );
  parseSignupFinishResponse(finishJson);

  return {
    canonicalEmail,
    secretKey,
    kek,
    km: vaultKeys.km,
    ks: vaultKeys.ks,
    wrappedKm: vaultKeys.wrappedKm,
    wrappedKsMaster: vaultKeys.wrappedKs,
    keyVersion: VAULT_KEY_VERSION_INITIAL,
    schemaVersion: VAULT_SCHEMA_VERSION_INITIAL,
  };
}

/**
 * Executes the client-side OPAQUE login ceremony:
 * 1. Canonicalizes email and derives `pw_input` from master password + Secret Key.
 * 2. Sends `/auth/login/start` and validates `kdf_params` BEFORE calling Argon2id WASM.
 * 3. Finishes OPAQUE login with explicit `argon2id-custom` parameters; discards `sessionKey`.
 * 4. Verifies `serverStaticPublicKey` against `expectedServerPublicKey` BEFORE deriving KEK or sending finish.
 * 5. Sends `/auth/login/finish` and derives the non-extractable KEK.
 *
 * Wrong password, wrong Secret Key, and unknown email all throw `AuthClientError("AUTH_FAILED", ...)`.
 */
export async function login(
  params: LoginParams,
  config: AuthClientConfig
): Promise<LoginResult> {
  const validatedConfig = validateConfig(config);
  const canonicalEmail = canonicalizeEmail(params.email);

  if (
    typeof params.masterPassword !== "string" ||
    params.masterPassword.length === 0
  ) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Master password must not be empty"
    );
  }

  const { opaqueImpl } = validatedConfig;
  const resolvedSecretKey = resolveLoginSecretKey(params.secretKey);
  try {
    await opaqueImpl.ready;

    const pwInput = await derivePwInput(
      params.masterPassword,
      resolvedSecretKey.bytes
    );
    const loginStart = opaqueImpl.client.startLogin({ password: pwInput });

    const startJson = await postJson(
      validatedConfig.fetchImpl,
      `${validatedConfig.baseUrl}/auth/login/start`,
      {
        email: canonicalEmail,
        credential_request: loginStart.startLoginRequest,
      },
      "login"
    );
    const { loginId, credentialResponse, kdfParams } =
      parseLoginStartResponse(startJson);

    let loginFinish: opaque.client.FinishLoginResult | undefined;
    try {
      loginFinish = opaqueImpl.client.finishLogin({
        clientLoginState: loginStart.clientLoginState,
        loginResponse: credentialResponse,
        password: pwInput,
        keyStretching: buildKeyStretchingConfig(kdfParams),
      });
    } catch {
      throw new AuthClientError("AUTH_FAILED", "Authentication failed");
    }

    if (loginFinish === undefined) {
      throw new AuthClientError("AUTH_FAILED", "Authentication failed");
    }

    // Must verify pinned server public key BEFORE deriving KEK or sending /login/finish.
    verifyPinnedServerPublicKey(
      loginFinish.serverStaticPublicKey,
      validatedConfig.expectedServerPublicKey
    );

    const finishBody: Record<string, string> = {
      login_id: loginId,
      credential_finalization: loginFinish.finishLoginRequest,
    };
    if (params.deviceId !== undefined) {
      finishBody["device_id"] = params.deviceId;
    }

    const finishJson = await postJson(
      validatedConfig.fetchImpl,
      `${validatedConfig.baseUrl}/auth/login/finish`,
      finishBody,
      "login",
      "include"
    );
    const status = parseLoginFinishResponse(finishJson);

    const exportKeyBytes = base64UrlToBytes(
      loginFinish.exportKey,
      "UNTRUSTED_SERVER",
      OPAQUE_EXPORT_KEY_BYTE_LENGTH
    );
    const kek = await deriveKek(exportKeyBytes, resolvedSecretKey.bytes);

    return {
      canonicalEmail,
      kek,
      status,
    };
  } finally {
    if (resolvedSecretKey.shouldZeroize) {
      zeroize(resolvedSecretKey.bytes);
    }
  }
}
