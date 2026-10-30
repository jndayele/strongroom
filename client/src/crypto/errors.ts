/**
 * Uniform cryptographic error types.
 *
 * Security rule (PRD Section 5.3, 10 & SECURITY_RULES.MD Rule 1, 5):
 * - All decryption and unwrapping failures throw the exact same generic
 *   DecryptionError with a static message.
 * - Error constructors accept no dynamic input or cause objects so that
 *   keys, plaintexts, ciphertexts, nonces, Secret Keys, or AAD values
 *   can never leak through error messages or stack traces.
 */

export const DECRYPTION_ERROR_MESSAGE = 'Decryption failed' as const;
export const INVALID_SECRET_KEY_MESSAGE = 'Invalid Secret Key' as const;
export const INVALID_CRYPTO_ARGUMENT_MESSAGE = 'Invalid cryptographic argument' as const;
export const WEBCRYPTO_UNAVAILABLE_MESSAGE = 'WebCrypto API is unavailable' as const;

export class DecryptionError extends Error {
  constructor() {
    super(DECRYPTION_ERROR_MESSAGE);
    this.name = 'DecryptionError';
    Object.setPrototypeOf(this, DecryptionError.prototype);
  }
}

export class InvalidSecretKeyError extends Error {
  constructor() {
    super(INVALID_SECRET_KEY_MESSAGE);
    this.name = 'InvalidSecretKeyError';
    Object.setPrototypeOf(this, InvalidSecretKeyError.prototype);
  }
}

export class CryptoArgumentError extends Error {
  constructor() {
    super(INVALID_CRYPTO_ARGUMENT_MESSAGE);
    this.name = 'CryptoArgumentError';
    Object.setPrototypeOf(this, CryptoArgumentError.prototype);
  }
}

export class WebCryptoUnavailableError extends Error {
  constructor() {
    super(WEBCRYPTO_UNAVAILABLE_MESSAGE);
    this.name = 'WebCryptoUnavailableError';
    Object.setPrototypeOf(this, WebCryptoUnavailableError.prototype);
  }
}
