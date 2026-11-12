export type AuthClientErrorCode =
  | "INVALID_INPUT"
  | "NETWORK"
  | "AUTH_FAILED"
  | "UNTRUSTED_SERVER";

/**
 * Uniform error thrown by `@strongroom/auth-client`.
 * Never surfaces raw server response text or sensitive key material.
 */
export class AuthClientError extends Error {
  public readonly code: AuthClientErrorCode;

  public constructor(code: AuthClientErrorCode, message: string) {
    super(message);
    this.name = "AuthClientError";
    this.code = code;
  }
}
