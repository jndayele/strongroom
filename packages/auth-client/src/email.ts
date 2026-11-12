import { AuthClientError } from "./errors.ts";

export const MAX_EMAIL_LENGTH = 254 as const;

/**
 * Canonicalizes an email address using the exact same rules as the Rust API (`apps/api/src/auth/email.rs`):
 * 1. Trims leading and trailing whitespace.
 * 2. Rejects empty strings.
 * 3. Rejects any non-ASCII character (`> 0x7F`).
 * 4. Enforces maximum length of 254 characters.
 * 5. Rejects any internal whitespace or ASCII control characters (`<= 0x20` or `0x7F`).
 * 6. Requires exactly one `@` with non-empty local part and non-empty domain.
 * 7. Converts all characters to ASCII lowercase.
 */
export function canonicalizeEmail(raw: string): string {
  if (typeof raw !== "string") {
    throw new AuthClientError("INVALID_INPUT", "Email must be a string");
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new AuthClientError("INVALID_INPUT", "Email must not be empty");
  }

  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed.charCodeAt(i) > 0x7f) {
      throw new AuthClientError(
        "INVALID_INPUT",
        "Email must contain only ASCII characters"
      );
    }
  }

  if (trimmed.length > MAX_EMAIL_LENGTH) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Email exceeds maximum length of 254 characters"
    );
  }

  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) {
      throw new AuthClientError(
        "INVALID_INPUT",
        "Email must not contain whitespace or control characters"
      );
    }
  }

  const parts = trimmed.split("@");
  if (parts.length !== 2) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Email must contain exactly one '@'"
    );
  }

  const local = parts[0] ?? "";
  const domain = parts[1] ?? "";
  if (local.length === 0) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Email local part must not be empty"
    );
  }
  if (domain.length === 0) {
    throw new AuthClientError(
      "INVALID_INPUT",
      "Email domain must not be empty"
    );
  }

  return trimmed.toLowerCase();
}
