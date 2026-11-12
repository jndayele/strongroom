import {
  aeadDecrypt,
  aeadEncrypt,
  buildAad,
  buildKeyWrapAad,
  generateSecretKey,
  randomBytes,
  unwrapKey,
} from "@strongroom/crypto";
import { describe, expect, it } from "vitest";
import {
  AuthClientError,
  type AuthClientConfig,
  login,
  signup,
} from "../../src/index.ts";

function readNodeEnv(name: string): string | undefined {
  const proc = (
    globalThis as {
      readonly process?: {
        readonly env?: Readonly<Record<string, string | undefined>>;
      };
    }
  ).process;
  return proc?.env?.[name];
}

function getIntegrationConfig(): AuthClientConfig {
  const baseUrl = readNodeEnv("STRONGROOM_API_URL");
  const expectedServerPublicKey = readNodeEnv(
    "STRONGROOM_EXPECTED_SERVER_PUBLIC_KEY"
  );

  if (!baseUrl || !expectedServerPublicKey) {
    throw new Error(
      "Missing STRONGROOM_API_URL or STRONGROOM_EXPECTED_SERVER_PUBLIC_KEY; run via `npm run test:integration`."
    );
  }

  return { baseUrl, expectedServerPublicKey };
}

function uniqueEmail(prefix: string): string {
  const bytes = randomBytes(8);
  let hex = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    hex += (bytes[i] ?? 0).toString(16).padStart(2, "0");
  }
  return `${prefix}-${hex}@Example.COM`;
}

describe("Cross-layer integration against real Rust strongroom-api", () => {
  it("completes signup and login, derives the identical KEK, unwraps K_m and K_s, and handles email casing/whitespace", async () => {
    const config = getIntegrationConfig();
    const rawSignupEmail = `  ${uniqueEmail("Alice.Integration")} \n`;
    const masterPassword = "correct-horse-battery-staple-99";

    const signupResult = await signup(
      { email: rawSignupEmail, masterPassword },
      config
    );

    expect(signupResult.kek.extractable).toBe(false);
    expect(signupResult.km.extractable).toBe(false);
    expect(signupResult.ks.extractable).toBe(false);
    expect(signupResult.keyVersion).toBe(1);
    expect(signupResult.schemaVersion).toBe(1);

    // Log in with differing casing and surrounding whitespace
    const messyLoginEmail = `\t${signupResult.canonicalEmail.toUpperCase()}  `;
    const loginResult = await login(
      {
        email: messyLoginEmail,
        masterPassword,
        secretKey: signupResult.secretKey,
      },
      config
    );

    expect(loginResult.canonicalEmail).toBe(signupResult.canonicalEmail);
    expect(loginResult.kek.extractable).toBe(false);
    expect(loginResult.status).toBe("mfa_required");

    // Prove KEK derived at signup equals KEK derived at login (both are non-extractable)
    const kekCheckAad = buildKeyWrapAad("K_m", 1, 1);
    const testSecret = new TextEncoder().encode("kek-equality-verification");
    const encryptedWithSignupKek = await aeadEncrypt(
      signupResult.kek,
      testSecret,
      kekCheckAad
    );
    const decryptedWithLoginKek = await aeadDecrypt(
      loginResult.kek,
      encryptedWithSignupKek,
      kekCheckAad
    );
    expect(decryptedWithLoginKek).toEqual(testSecret);

    // Unwrap K_m and K_s using the login KEK and the blobs returned at signup
    const kmAad = buildKeyWrapAad(
      "K_m",
      signupResult.keyVersion,
      signupResult.schemaVersion
    );
    const ksAad = buildKeyWrapAad(
      "K_s",
      signupResult.keyVersion,
      signupResult.schemaVersion
    );

    const unwrappedKm = await unwrapKey(
      loginResult.kek,
      signupResult.wrappedKm,
      kmAad
    );
    const unwrappedKs = await unwrapKey(
      loginResult.kek,
      signupResult.wrappedKsMaster,
      ksAad
    );
    expect(unwrappedKm.extractable).toBe(false);
    expect(unwrappedKs.extractable).toBe(false);

    // Prove unwrapped K_m and K_s match the keys generated at signup
    const itemMetaAad = buildAad("user-integration", "item-1", 1, 1);
    const metaPlaintext = new TextEncoder().encode('{"title":"Bank"}');
    const metaCiphertext = await aeadEncrypt(
      signupResult.km,
      metaPlaintext,
      itemMetaAad
    );
    expect(await aeadDecrypt(unwrappedKm, metaCiphertext, itemMetaAad)).toEqual(
      metaPlaintext
    );

    const itemSecretAad = buildAad("user-integration", "item-1-secret", 1, 1);
    const secretPlaintext = new TextEncoder().encode("s3cr3t-p4ss");
    const secretCiphertext = await aeadEncrypt(
      signupResult.ks,
      secretPlaintext,
      itemSecretAad
    );
    expect(
      await aeadDecrypt(unwrappedKs, secretCiphertext, itemSecretAad)
    ).toEqual(secretPlaintext);

    // Logging in with formatted Secret Key string also succeeds
    const loginWithFormattedSk = await login(
      {
        email: signupResult.canonicalEmail,
        masterPassword,
        secretKey: signupResult.secretKey.formatted,
      },
      config
    );
    expect(
      await aeadDecrypt(
        loginWithFormattedSk.kek,
        encryptedWithSignupKek,
        kekCheckAad
      )
    ).toEqual(testSecret);
  });

  it("rejects wrong master password, wrong Secret Key, and unknown email with the exact same AUTH_FAILED error", async () => {
    const config = getIntegrationConfig();
    const email = uniqueEmail("bob-fail");
    const masterPassword = "very-strong-master-password";

    const signupResult = await signup({ email, masterPassword }, config);

    const captureAuthError = async (
      fn: () => Promise<unknown>
    ): Promise<AuthClientError> => {
      try {
        await fn();
        throw new Error("Expected login failure");
      } catch (err) {
        expect(err).toBeInstanceOf(AuthClientError);
        return err as AuthClientError;
      }
    };

    const wrongPasswordErr = await captureAuthError(() =>
      login(
        {
          email,
          masterPassword: "wrong-master-password",
          secretKey: signupResult.secretKey,
        },
        config
      )
    );

    const wrongSecretKeyErr = await captureAuthError(() =>
      login(
        {
          email,
          masterPassword,
          secretKey: generateSecretKey(),
        },
        config
      )
    );

    const unknownEmailErr = await captureAuthError(() =>
      login(
        {
          email: uniqueEmail("unknown-user"),
          masterPassword,
          secretKey: signupResult.secretKey,
        },
        config
      )
    );

    expect(wrongPasswordErr.code).toBe("AUTH_FAILED");
    expect(wrongSecretKeyErr.code).toBe("AUTH_FAILED");
    expect(unknownEmailErr.code).toBe("AUTH_FAILED");

    expect(wrongPasswordErr.message).toBe(wrongSecretKeyErr.message);
    expect(wrongSecretKeyErr.message).toBe(unknownEmailErr.message);
  });
});
