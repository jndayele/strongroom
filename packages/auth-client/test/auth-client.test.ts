import * as opaque from "@serenity-kit/opaque";
import {
  hkdfDeriveBytes,
  KDF_LABEL_PW_INPUT_V1,
  SECRET_KEY_BYTE_LENGTH,
  generateSecretKey,
  randomBytes,
} from "@strongroom/crypto";
import { describe, expect, it, vi } from "vitest";
import emailVectors from "../../../docs/test-vectors/email.json";
import { bytesToBase64Url } from "../src/base64url.ts";
import {
  AuthClientError,
  type FetchFn,
  KDF_MAX_ITERATIONS,
  KDF_MAX_MEMORY_KIB,
  KDF_MAX_PARALLELISM,
  KDF_MIN_ITERATIONS,
  KDF_MIN_MEMORY_KIB,
  KDF_MIN_PARALLELISM,
  canonicalizeEmail,
  deriveKek,
  derivePwInput,
  encodeLengthPrefixedPair,
  login,
  signup,
  validateKdfParams,
} from "../src/index.ts";

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    out += (bytes[i] ?? 0).toString(16).padStart(2, "0");
  }
  return out;
}

describe("1. Shared email canonicalization test vectors", () => {
  it("matches every case in docs/test-vectors/email.json", () => {
    expect(emailVectors.cases.length).toBeGreaterThan(0);

    for (const testCase of emailVectors.cases) {
      if (testCase.expected !== null) {
        expect(canonicalizeEmail(testCase.input)).toBe(testCase.expected);
      } else {
        try {
          canonicalizeEmail(testCase.input);
          expect.unreachable(
            `Expected canonicalizeEmail(${JSON.stringify(testCase.input)}) to throw`
          );
        } catch (err) {
          expect(err).toBeInstanceOf(AuthClientError);
          expect((err as AuthClientError).code).toBe("INVALID_INPUT");
        }
      }
    }
  });
});

describe("2. validateKdfParams bounds enforcement", () => {
  it("accepts boundary and valid mid-range Argon2id parameters", () => {
    const validCases = [
      {
        memory: KDF_MIN_MEMORY_KIB,
        iterations: KDF_MIN_ITERATIONS,
        parallelism: KDF_MIN_PARALLELISM,
      },
      {
        memory: KDF_MAX_MEMORY_KIB,
        iterations: KDF_MAX_ITERATIONS,
        parallelism: KDF_MAX_PARALLELISM,
      },
      { memory: 131_072, iterations: 4, parallelism: 2 },
    ];

    for (const candidate of validCases) {
      expect(validateKdfParams(candidate)).toEqual(candidate);
    }
  });

  it("rejects out-of-range, non-integer, malformed, and unknown-field KDF params with UNTRUSTED_SERVER", () => {
    const invalidCases: unknown[] = [
      null,
      undefined,
      "fast",
      123,
      [],
      {},
      { memory: 65_535, iterations: 3, parallelism: 1 },
      { memory: 524_289, iterations: 3, parallelism: 1 },
      { memory: 8, iterations: 1, parallelism: 1 },
      { memory: 2_097_151, iterations: 3, parallelism: 1 },
      { memory: 65_536, iterations: 2, parallelism: 1 },
      { memory: 65_536, iterations: 11, parallelism: 1 },
      { memory: 65_536, iterations: 3, parallelism: 0 },
      { memory: 65_536, iterations: 3, parallelism: 5 },
      { memory: 65_536.5, iterations: 3, parallelism: 1 },
      { memory: 65_536, iterations: 3.1, parallelism: 1 },
      { memory: 65_536, iterations: 3, parallelism: 1.5 },
      { memory: Number.NaN, iterations: 3, parallelism: 1 },
      { memory: Number.POSITIVE_INFINITY, iterations: 3, parallelism: 1 },
      { memory: "65536", iterations: 3, parallelism: 1 },
      { memory: 65_536, iterations: 3 },
      { memory: 65_536, iterations: 3, parallelism: 1, extra: true },
    ];

    for (const candidate of invalidCases) {
      try {
        validateKdfParams(candidate);
        expect.unreachable(
          `Expected validateKdfParams(${JSON.stringify(candidate)}) to throw`
        );
      } catch (err) {
        expect(err).toBeInstanceOf(AuthClientError);
        expect((err as AuthClientError).code).toBe("UNTRUSTED_SERVER");
      }
    }
  });
});

describe("3. Key derivation (derivePwInput and deriveKek)", () => {
  it("derivePwInput is deterministic, sensitive to password and Secret Key, NFKC-normalizes, and preserves framing", async () => {
    const sk1 = generateSecretKey();
    const sk2 = generateSecretKey();
    const sk1Copy = new Uint8Array(sk1.rawBytes);

    const pw1 = await derivePwInput("correct-horse-battery-staple", sk1);
    const pw1Again = await derivePwInput("correct-horse-battery-staple", sk1Copy);
    expect(pw1).toBe(pw1Again);
    // Caller's secretKey buffer must not be wiped by derivePwInput
    expect(sk1.rawBytes.every((b) => b === 0)).toBe(false);

    // Changing either masterPassword or Secret Key changes pw_input
    const pwDifferentPassword = await derivePwInput(
      "correct-horse-battery-stapl3",
      sk1
    );
    const pwDifferentSk = await derivePwInput(
      "correct-horse-battery-staple",
      sk2
    );
    expect(pwDifferentPassword).not.toBe(pw1);
    expect(pwDifferentSk).not.toBe(pw1);

    // Composed ("é" = U+00E9) and decomposed ("e" + U+0301) Unicode must produce identical output
    const composed = await derivePwInput("caf\u00e9-passphrase", sk1);
    const decomposed = await derivePwInput("cafe\u0301-passphrase", sk1);
    expect(composed).toBe(decomposed);

    // Length-ambiguous splits ("ab"+"c" vs "a"+"bc") produce distinct framing and distinct HKDF output
    const enc = new TextEncoder();
    const split1 = encodeLengthPrefixedPair(enc.encode("ab"), enc.encode("c"));
    const split2 = encodeLengthPrefixedPair(enc.encode("a"), enc.encode("bc"));
    expect(bytesToHex(split1)).not.toBe(bytesToHex(split2));

    const hkdf1 = await hkdfDeriveBytes(
      split1,
      new Uint8Array(0),
      KDF_LABEL_PW_INPUT_V1,
      32
    );
    const hkdf2 = await hkdfDeriveBytes(
      split2,
      new Uint8Array(0),
      KDF_LABEL_PW_INPUT_V1,
      32
    );
    expect(bytesToHex(hkdf1)).not.toBe(bytesToHex(hkdf2));
  });

  it("deriveKek produces a non-extractable AES-256-GCM CryptoKey and wipes exportKeyBytes", async () => {
    const exportKey = randomBytes(64);
    const exportKeyBefore = bytesToHex(exportKey);
    expect(exportKeyBefore).not.toBe("00".repeat(64));

    const secretKeyBytes = randomBytes(SECRET_KEY_BYTE_LENGTH);
    const kek = await deriveKek(exportKey, secretKeyBytes);

    expect(kek.extractable).toBe(false);
    expect(kek.type).toBe("secret");
    expect(kek.algorithm.name).toBe("AES-GCM");
    expect((kek.algorithm as AesKeyAlgorithm).length).toBe(256);
    expect(kek.usages).toContain("encrypt");
    expect(kek.usages).toContain("decrypt");

    // Exporting a non-extractable key must fail
    await expect(
      globalThis.crypto.subtle.exportKey("raw", kek)
    ).rejects.toThrow();

    // exportKeyBytes must be zeroed in place
    expect(exportKey.every((b) => b === 0)).toBe(true);
  });
});

describe("4. Rogue server defense (pinned server public key and KDF bounds)", () => {
  it("aborts signup with UNTRUSTED_SERVER when serverStaticPublicKey does not match pinned key (before sending finish)", async () => {
    await opaque.ready;
    const pinnedSetup = opaque.server.createSetup();
    const rogueSetup = opaque.server.createSetup();
    const pinnedPublicKey = opaque.server.getPublicKey(pinnedSetup);

    const calledUrls: string[] = [];
    const mockFetch: FetchFn = async (input, init) => {
      const url = typeof input === "string" ? input : input.toString();
      calledUrls.push(url);
      expect(init?.credentials).toBe("omit");

      const body = JSON.parse(String(init?.body)) as {
        email: string;
        registration_request: string;
      };
      const serverReg = opaque.server.createRegistrationResponse({
        serverSetup: rogueSetup,
        userIdentifier: body.email,
        registrationRequest: body.registration_request,
      });

      return new Response(
        JSON.stringify({
          registration_response: serverReg.registrationResponse,
          kdf_params: { memory: 65_536, iterations: 3, parallelism: 1 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    await expect(
      signup(
        { email: "alice@example.com", masterPassword: "test-master-password" },
        {
          baseUrl: "https://api.example.test",
          expectedServerPublicKey: pinnedPublicKey,
          fetch: mockFetch,
        }
      )
    ).rejects.toMatchObject({ code: "UNTRUSTED_SERVER" });

    // Must abort BEFORE sending /auth/signup/finish
    expect(calledUrls).toEqual(["https://api.example.test/auth/signup/start"]);
  });

  it("aborts login with UNTRUSTED_SERVER when serverStaticPublicKey does not match pinned key (before sending finish)", async () => {
    await opaque.ready;
    const pinnedSetup = opaque.server.createSetup();
    const rogueSetup = opaque.server.createSetup();
    const pinnedPublicKey = opaque.server.getPublicKey(pinnedSetup);

    const email = "rogue-login@example.com";
    const masterPassword = "correct-master-password";
    const secretKey = generateSecretKey();
    const pwInput = await derivePwInput(masterPassword, secretKey.rawBytes);

    // Pre-register user against the ROGUE server setup so finishLogin cryptographically opens
    // and returns the rogue serverStaticPublicKey.
    const kdf = {
      "argon2id-custom": { memory: 65_536, iterations: 3, parallelism: 1 },
    };
    const regStart = opaque.client.startRegistration({ password: pwInput });
    const regResp = opaque.server.createRegistrationResponse({
      serverSetup: rogueSetup,
      userIdentifier: email,
      registrationRequest: regStart.registrationRequest,
    });
    const regFinish = opaque.client.finishRegistration({
      clientRegistrationState: regStart.clientRegistrationState,
      registrationResponse: regResp.registrationResponse,
      password: pwInput,
      keyStretching: kdf,
    });

    const calledUrls: string[] = [];
    const mockFetch: FetchFn = async (input, init) => {
      const url = typeof input === "string" ? input : input.toString();
      calledUrls.push(url);
      expect(init?.credentials).toBe("omit");

      const body = JSON.parse(String(init?.body)) as {
        credential_request: string;
      };
      const loginResp = opaque.server.startLogin({
        serverSetup: rogueSetup,
        registrationRecord: regFinish.registrationRecord,
        startLoginRequest: body.credential_request,
        userIdentifier: email,
      });

      const fakeLoginId = bytesToBase64Url(randomBytes(32));
      return new Response(
        JSON.stringify({
          login_id: fakeLoginId,
          credential_response: loginResp.loginResponse,
          kdf_params: { memory: 65_536, iterations: 3, parallelism: 1 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    await expect(
      login(
        { email, masterPassword, secretKey },
        {
          baseUrl: "https://api.example.test",
          expectedServerPublicKey: pinnedPublicKey,
          fetch: mockFetch,
        }
      )
    ).rejects.toMatchObject({ code: "UNTRUSTED_SERVER" });

    // Must abort BEFORE sending /auth/login/finish
    expect(calledUrls).toEqual(["https://api.example.test/auth/login/start"]);
  });

  it("aborts signup and login with UNTRUSTED_SERVER on out-of-range kdf_params BEFORE any Argon2 WASM call", async () => {
    await opaque.ready;
    const setup = opaque.server.createSetup();
    const publicKey = opaque.server.getPublicKey(setup);
    const secretKey = generateSecretKey();

    const finishRegSpy = vi.fn(opaque.client.finishRegistration);
    const finishLoginSpy = vi.fn(opaque.client.finishLogin);
    const spiedAdapter = {
      ready: opaque.ready,
      client: {
        startRegistration: opaque.client.startRegistration,
        finishRegistration: finishRegSpy,
        startLogin: opaque.client.startLogin,
        finishLogin: finishLoginSpy,
      },
    };

    // 1. Downgrade attack during signup (memory = 8 KiB, iterations = 1)
    const signupMockFetch: FetchFn = async (input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        email: string;
        registration_request: string;
      };
      const resp = opaque.server.createRegistrationResponse({
        serverSetup: setup,
        userIdentifier: body.email,
        registrationRequest: body.registration_request,
      });
      expect(String(input)).toContain("/auth/signup/start");
      return new Response(
        JSON.stringify({
          registration_response: resp.registrationResponse,
          kdf_params: { memory: 8, iterations: 1, parallelism: 1 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    await expect(
      signup(
        { email: "downgrade@example.com", masterPassword: "strong-password" },
        {
          baseUrl: "https://api.example.test",
          expectedServerPublicKey: publicKey,
          fetch: signupMockFetch,
          opaqueAdapter: spiedAdapter,
        }
      )
    ).rejects.toMatchObject({ code: "UNTRUSTED_SERVER" });
    expect(finishRegSpy).not.toHaveBeenCalled();

    // 2. DoS / OOM attack during login (memory = 1 GiB)
    const loginMockFetch: FetchFn = async (input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        email: string;
        credential_request: string;
      };
      const resp = opaque.server.startLogin({
        serverSetup: setup,
        registrationRecord: undefined,
        startLoginRequest: body.credential_request,
        userIdentifier: body.email,
      });
      expect(String(input)).toContain("/auth/login/start");
      return new Response(
        JSON.stringify({
          login_id: bytesToBase64Url(randomBytes(32)),
          credential_response: resp.loginResponse,
          kdf_params: { memory: 1_048_576, iterations: 3, parallelism: 1 },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    await expect(
      login(
        {
          email: "oom@example.com",
          masterPassword: "strong-password",
          secretKey,
        },
        {
          baseUrl: "https://api.example.test",
          expectedServerPublicKey: publicKey,
          fetch: loginMockFetch,
          opaqueAdapter: spiedAdapter,
        }
      )
    ).rejects.toMatchObject({ code: "UNTRUSTED_SERVER" });
    expect(finishLoginSpy).not.toHaveBeenCalled();
  });

  it("never surfaces raw server error text", async () => {
    await opaque.ready;
    const setup = opaque.server.createSetup();
    const publicKey = opaque.server.getPublicKey(setup);
    const secretKey = generateSecretKey();

    const secretServerText = "SENSITIVE_INTERNAL_DB_ERROR_LEAK_12345";
    const leakyFetch: FetchFn = async () =>
      new Response(JSON.stringify({ error: secretServerText }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });

    try {
      await login(
        {
          email: "leak-check@example.com",
          masterPassword: "strong-password",
          secretKey,
        },
        {
          baseUrl: "https://api.example.test",
          expectedServerPublicKey: publicKey,
          fetch: leakyFetch,
        }
      );
      expect.unreachable("Expected login to reject on HTTP 500");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthClientError);
      const authErr = err as AuthClientError;
      expect(authErr.code).toBe("NETWORK");
      expect(authErr.message).not.toContain(secretServerText);
    }
  });
});
