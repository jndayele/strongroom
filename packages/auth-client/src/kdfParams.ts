import { AuthClientError } from "./errors.ts";

export const KDF_MIN_MEMORY_KIB = 65_536 as const;
export const KDF_MAX_MEMORY_KIB = 524_288 as const;
export const KDF_MIN_ITERATIONS = 3 as const;
export const KDF_MAX_ITERATIONS = 10 as const;
export const KDF_MIN_PARALLELISM = 1 as const;
export const KDF_MAX_PARALLELISM = 4 as const;

export interface KdfParams {
  readonly memory: number;
  readonly iterations: number;
  readonly parallelism: number;
}

function assertIntegerInRange(
  value: unknown,
  min: number,
  max: number,
  field: string
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < min ||
    value > max
  ) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      `Server returned invalid or out-of-range Argon2 parameter: ${field}`
    );
  }
  return value;
}

/**
 * Strictly validates server-returned Argon2id parameters BEFORE any WASM call.
 * Prevents a compromised server from downgrading KDF work or exhausting browser memory.
 */
export function validateKdfParams(params: unknown): KdfParams {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned malformed KDF parameters"
    );
  }

  const record = params as Record<string, unknown>;
  const keys = Object.keys(record);
  if (
    keys.length !== 3 ||
    !Object.prototype.hasOwnProperty.call(record, "memory") ||
    !Object.prototype.hasOwnProperty.call(record, "iterations") ||
    !Object.prototype.hasOwnProperty.call(record, "parallelism")
  ) {
    throw new AuthClientError(
      "UNTRUSTED_SERVER",
      "Server returned unexpected KDF parameter fields"
    );
  }

  const memory = assertIntegerInRange(
    record["memory"],
    KDF_MIN_MEMORY_KIB,
    KDF_MAX_MEMORY_KIB,
    "memory"
  );
  const iterations = assertIntegerInRange(
    record["iterations"],
    KDF_MIN_ITERATIONS,
    KDF_MAX_ITERATIONS,
    "iterations"
  );
  const parallelism = assertIntegerInRange(
    record["parallelism"],
    KDF_MIN_PARALLELISM,
    KDF_MAX_PARALLELISM,
    "parallelism"
  );

  return { memory, iterations, parallelism };
}
