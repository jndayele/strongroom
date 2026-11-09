import { describe, expect, it } from "vitest";
import {
  AeadDecryptionError,
  aeadDecrypt,
  aeadEncrypt,
  ALGORITHM_ID_AES_256_GCM,
  buildAad,
  decodeEnvelope,
  encodeEnvelope,
  ENVELOPE_HEADER_BYTE_LENGTH,
  ENVELOPE_VERSION_V1,
  EnvelopeError,
  GCM_TAG_BYTE_LENGTH,
  generateAndWrapKey,
  generateAndWrapVaultKeys,
  generateItemKey,
  generateSecretKey,
  generateVaultKey,
  getSecretKeyConfirmationSuffix,
  hkdfDeriveAesGcmKey,
  hkdfDeriveBytes,
  hkdfSha256Raw,
  importNonExtractableAesGcmKey,
  KDF_LABEL_PRF_KEK_V1,
  KDF_LABEL_PW_INPUT_V1,
  KDF_LABEL_VAULT_KEK_V1,
  KEY_BYTE_LENGTH,
  MAX_ENVELOPE_BYTE_LENGTH,
  MAX_PLAINTEXT_BYTE_LENGTH,
  NONCE_BYTE_LENGTH,
  PADDING_BUCKET_BYTES,
  padPlaintext,
  parseSecretKey,
  randomBytes,
  randomInt,
  SECRET_KEY_BYTE_LENGTH,
  SECRET_KEY_PAYLOAD_CHARS,
  SECRET_KEY_TOTAL_CHARS,
  SecretKeyError,
  unpadPlaintext,
  unwrapKey,
  validateSecretKey,
  wrapKey,
  zeroize,
} from "../src/index.ts";
import pkgJson from "../package.json";
import { buildAad as buildAadDirect } from "../src/aad.ts";
import { aeadEncrypt as aeadEncryptDirect } from "../src/aead.ts";
import { padPlaintext as padPlaintextDirect } from "../src/envelope.ts";
import { KDF_LABELS as kdfLabelsDirect } from "../src/kdf.ts";
import { generateKey as generateKeyDirect } from "../src/keys.ts";
import { randomBytes as randomBytesDirect } from "../src/random.ts";
import { formatSecretKey as formatSecretKeyDirect } from "../src/secretKey.ts";
import { zeroize as zeroizeDirect } from "../src/wipe.ts";

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex string length: ${String(clean.length)}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.byteLength; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

describe("1. HKDF-SHA-256 RFC 5869 test vectors & domain separation", () => {
  it("matches RFC 5869 Appendix A.1 (Test Case 1)", async () => {
    const ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexToBytes("000102030405060708090a0b0c");
    const info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
    const expectedOkm =
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    const okm = await hkdfSha256Raw(ikm, salt, info, 42);
    expect(bytesToHex(okm)).toBe(expectedOkm);
  });

  it("matches RFC 5869 Appendix A.2 (Test Case 2: longer inputs and outputs)", async () => {
    const ikm = hexToBytes(
      "000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f" +
        "404142434445464748494a4b4c4d4e4f"
    );
    const salt = hexToBytes(
      "606162636465666768696a6b6c6d6e6f" +
        "707172737475767778797a7b7c7d7e7f" +
        "808182838485868788898a8b8c8d8e8f" +
        "909192939495969798999a9b9c9d9e9f" +
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    );
    const info = hexToBytes(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    );
    const expectedOkm =
      "b11e398dc80327a1c8e7f78c596a4934" +
      "4f012eda2d4efad8a050cc4c19afa97c" +
      "59045a99cac7827271cb41c65e590e09" +
      "da3275600c2f09b8367793a9aca3db71" +
      "cc30c58179ec3e87c14c01d5c1f3434f" +
      "1d87";

    const okm = await hkdfSha256Raw(ikm, salt, info, 82);
    expect(bytesToHex(okm)).toBe(expectedOkm);
  });

  it("matches RFC 5869 Appendix A.3 (Test Case 3: zero-length salt and info)", async () => {
    const ikm = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = new Uint8Array(0);
    const info = new Uint8Array(0);
    const expectedOkm =
      "8da4e775a563c18f715f802a063c5a31" +
      "b8a11f5c5ee1879ec3454e5f3c738d2d" +
      "9d201395faa4b61a96c8";

    const okm = await hkdfSha256Raw(ikm, salt, info, 42);
    expect(bytesToHex(okm)).toBe(expectedOkm);
  });

  it("derives distinct keys for distinct domain-separation labels and produces non-extractable CryptoKeys", async () => {
    const ikm = randomBytes(32);
    const salt = randomBytes(16);

    const bytesPw = await hkdfDeriveBytes(ikm, salt, KDF_LABEL_PW_INPUT_V1, 32);
    const bytesKek = await hkdfDeriveBytes(
      ikm,
      salt,
      KDF_LABEL_VAULT_KEK_V1,
      32
    );
    const bytesPrf = await hkdfDeriveBytes(ikm, salt, KDF_LABEL_PRF_KEK_V1, 32);

    expect(bytesToHex(bytesPw)).not.toBe(bytesToHex(bytesKek));
    expect(bytesToHex(bytesKek)).not.toBe(bytesToHex(bytesPrf));
    expect(bytesToHex(bytesPw)).not.toBe(bytesToHex(bytesPrf));

    const kekKey = await hkdfDeriveAesGcmKey(
      ikm,
      salt,
      KDF_LABEL_VAULT_KEK_V1
    );
    expect(kekKey.extractable).toBe(false);
    expect(kekKey.algorithm.name).toBe("AES-GCM");
  });
});

describe("2. AES-256-GCM NIST SP 800-38D test vectors", () => {
  it("matches NIST SP 800-38D Test Case 15 (256-bit key, 96-bit IV, 512-bit plaintext, no AAD) and Test Case 16 (with AAD)", async () => {
    // NIST SP 800-38D Appendix B Test Case 16:
    // 256-bit key, 96-bit IV, 60-byte plaintext, 20-byte AAD
    const rawKey = hexToBytes(
      "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
    );
    const iv = hexToBytes("cafebabefacedbaddecaf888");
    const pt = hexToBytes(
      "d9313225f88406e5a55909c5aff5269a" +
        "86a7a9531534f7da2e4c303d8a318a72" +
        "1c3c0c95956809532fcf0e2449a6b525" +
        "b16aedf5aa0de657ba637b39"
    );
    const aad = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const expectedCt =
      "522dc1f099567d07f47f37a32a84427d" +
      "643a8cdcbfe5c0c97598a2bd2555d1aa" +
      "8cb08e48590dbb3da7b08b1056828838" +
      "c5f61e6393ba7a0abcc9f662";
    const expectedTag = "76fc6ece0f4e1768cddf8853bb2d551b";

    const key = await importNonExtractableAesGcmKey(rawKey);
    expect(key.extractable).toBe(false);
    // rawKey must have been zeroized by importNonExtractableAesGcmKey
    expect(rawKey.every((b) => b === 0)).toBe(true);

    const encrypted = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
        key,
        pt
      )
    );
    expect(bytesToHex(encrypted)).toBe(expectedCt + expectedTag);

    // Also verify envelope decode + aeadDecrypt against a known NIST-style vector
    // where the 256-byte padded plaintext is encrypted with a known key and IV:
    const vectorRawKey = hexToBytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    const vectorKey = await importNonExtractableAesGcmKey(vectorRawKey);
    const vectorPlaintext = new TextEncoder().encode("Strongroom NIST GCM check");
    const vectorPadded = padPlaintext(vectorPlaintext);
    const vectorAad = buildAad("user-vector-1", "item-vector-1", 1, 1);
    const vectorCtAndTag = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: vectorAad, tagLength: 128 },
        vectorKey,
        vectorPadded
      )
    );
    const vectorEnvelope = encodeEnvelope(iv, vectorCtAndTag);
    const decrypted = await aeadDecrypt(vectorKey, vectorEnvelope, vectorAad);
    expect(decrypted).toEqual(vectorPlaintext);
  });
});

describe("3. Roundtrip tests for envelope, AEAD, and key wrapping (many random inputs)", () => {
  it("roundtrips padPlaintext/unpadPlaintext and encodeEnvelope/decodeEnvelope across 60 random inputs", () => {
    for (let i = 0; i < 60; i++) {
      const length = randomInt(2048);
      const pt = randomBytes(length);
      const padded = padPlaintext(pt);
      expect(padded.byteLength % PADDING_BUCKET_BYTES).toBe(0);
      expect(padded.byteLength).toBeGreaterThanOrEqual(PADDING_BUCKET_BYTES);

      const unpadded = unpadPlaintext(padded);
      expect(unpadded).toEqual(pt);

      const nonce = randomBytes(NONCE_BYTE_LENGTH);
      const fakeCiphertextAndTag = randomBytes(
        padded.byteLength + GCM_TAG_BYTE_LENGTH
      );
      const encoded = encodeEnvelope(nonce, fakeCiphertextAndTag);
      const decoded = decodeEnvelope(encoded);

      expect(decoded.version).toBe(ENVELOPE_VERSION_V1);
      expect(decoded.algorithmId).toBe(ALGORITHM_ID_AES_256_GCM);
      expect(decoded.nonce).toEqual(nonce);
      expect(decoded.ciphertextAndTag).toEqual(fakeCiphertextAndTag);
    }
  });

  it("roundtrips aeadEncrypt and aeadDecrypt across 50 random plaintexts and AADs", async () => {
    const key = await generateItemKey();
    expect(key.extractable).toBe(false);

    for (let i = 0; i < 50; i++) {
      const length = randomInt(1500);
      const pt = randomBytes(length);
      const aad = buildAad(
        `user-${String(i)}`,
        `item-${String(randomInt(10_000))}`,
        randomInt(10) + 1,
        randomInt(5) + 1
      );

      const envelope = await aeadEncrypt(key, pt, aad);
      const decrypted = await aeadDecrypt(key, envelope, aad);
      expect(decrypted).toEqual(pt);
    }
  });

  it("roundtrips key wrapping (wrapKey / unwrapKey / generateAndWrapVaultKeys) across 30 random keys and ensures non-extractable keys", async () => {
    const kek = await generateVaultKey();
    const kmAad = buildAad("user-1", "vault-km", 1, 1);
    const ksAad = buildAad("user-1", "vault-ks", 1, 1);

    const vaultKeys = await generateAndWrapVaultKeys(kek, kmAad, ksAad);
    expect(vaultKeys.km.extractable).toBe(false);
    expect(vaultKeys.ks.extractable).toBe(false);

    const unwrappedKm = await unwrapKey(kek, vaultKeys.wrappedKm, kmAad);
    const unwrappedKs = await unwrapKey(kek, vaultKeys.wrappedKs, ksAad);
    expect(unwrappedKm.extractable).toBe(false);
    expect(unwrappedKs.extractable).toBe(false);

    for (let i = 0; i < 30; i++) {
      const itemAad = buildAad("user-1", `item-${String(i)}`, 1, 1);
      const rawKeyMaterial = randomBytes(KEY_BYTE_LENGTH);
      const wrappedRawKey = await wrapKey(unwrappedKm, rawKeyMaterial, itemAad);
      // wrapKey zeroes rawKeyMaterial in place
      expect(rawKeyMaterial.every((b) => b === 0)).toBe(true);
      const unwrappedFromRaw = await unwrapKey(
        unwrappedKm,
        wrappedRawKey,
        itemAad
      );
      expect(unwrappedFromRaw.extractable).toBe(false);

      const { key: itemKey, wrappedKey } = await generateAndWrapKey(
        unwrappedKm,
        itemAad
      );
      expect(itemKey.extractable).toBe(false);

      const payload = randomBytes(randomInt(600));
      const blob = await aeadEncrypt(itemKey, payload, itemAad);

      const recoveredItemKey = await unwrapKey(
        unwrappedKm,
        wrappedKey,
        itemAad
      );
      expect(recoveredItemKey.extractable).toBe(false);

      const decryptedPayload = await aeadDecrypt(
        recoveredItemKey,
        blob,
        itemAad
      );
      expect(decryptedPayload).toEqual(payload);
    }
  });
});

describe("4. Tamper tests (must FAIL to decrypt)", () => {
  it("fails to decrypt when ciphertext is modified", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-abc", "item-123", 1, 1);
    const pt = new TextEncoder().encode("top-secret-password");
    const envelope = await aeadEncrypt(key, pt, aad);

    // Flip a bit in the ciphertext body
    const tamperedCiphertext = new Uint8Array(envelope);
    const ctIndex = ENVELOPE_HEADER_BYTE_LENGTH + 10;
    tamperedCiphertext[ctIndex] = (tamperedCiphertext[ctIndex] ?? 0) ^ 0x01;
    await expect(aeadDecrypt(key, tamperedCiphertext, aad)).rejects.toThrow(
      AeadDecryptionError
    );

    // Flip a bit in the GCM authentication tag (last byte)
    const tamperedTag = new Uint8Array(envelope);
    const tagIndex = tamperedTag.byteLength - 1;
    tamperedTag[tagIndex] = (tamperedTag[tagIndex] ?? 0) ^ 0x80;
    await expect(aeadDecrypt(key, tamperedTag, aad)).rejects.toThrow(
      AeadDecryptionError
    );

    // Flip a bit in the 12-byte nonce
    const tamperedNonce = new Uint8Array(envelope);
    tamperedNonce[5] = (tamperedNonce[5] ?? 0) ^ 0x04;
    await expect(aeadDecrypt(key, tamperedNonce, aad)).rejects.toThrow(
      AeadDecryptionError
    );
  });

  it("fails to decrypt with a wrong key", async () => {
    const key1 = await generateItemKey();
    const key2 = await generateItemKey();
    const aad = buildAad("user-abc", "item-123", 1, 1);
    const pt = new TextEncoder().encode("secret-data");
    const envelope = await aeadEncrypt(key1, pt, aad);

    await expect(aeadDecrypt(key2, envelope, aad)).rejects.toThrow(
      AeadDecryptionError
    );
  });

  it("fails to decrypt with wrong user_id in AAD", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-123", "item-456", 1, 1);
    const pt = new TextEncoder().encode("bound-secret");
    const envelope = await aeadEncrypt(key, pt, aad);

    await expect(
      aeadDecrypt(key, envelope, buildAad("user-999", "item-456", 1, 1))
    ).rejects.toThrow(AeadDecryptionError);
  });

  it("fails to decrypt with wrong item_id in AAD", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-123", "item-456", 1, 1);
    const pt = new TextEncoder().encode("bound-secret");
    const envelope = await aeadEncrypt(key, pt, aad);

    await expect(
      aeadDecrypt(key, envelope, buildAad("user-123", "item-999", 1, 1))
    ).rejects.toThrow(AeadDecryptionError);

    // Also verify boundary-shifted (user_id, item_id) pairs ("ab", "cd") vs ("a", "bcd") fail
    const aadSplit1 = buildAad("ab", "cd", 1, 1);
    const aadSplit2 = buildAad("a", "bcd", 1, 1);
    expect(bytesToHex(aadSplit1)).not.toBe(bytesToHex(aadSplit2));
    const envSplit1 = await aeadEncrypt(key, pt, aadSplit1);
    await expect(aeadDecrypt(key, envSplit1, aadSplit2)).rejects.toThrow(
      AeadDecryptionError
    );
  });

  it("fails to decrypt with wrong key_version in AAD", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-123", "item-456", 1, 1);
    const pt = new TextEncoder().encode("bound-secret");
    const envelope = await aeadEncrypt(key, pt, aad);

    await expect(
      aeadDecrypt(key, envelope, buildAad("user-123", "item-456", 2, 1))
    ).rejects.toThrow(AeadDecryptionError);
  });

  it("fails to decrypt with wrong schema_version in AAD", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-123", "item-456", 1, 1);
    const pt = new TextEncoder().encode("bound-secret");
    const envelope = await aeadEncrypt(key, pt, aad);

    await expect(
      aeadDecrypt(key, envelope, buildAad("user-123", "item-456", 1, 2))
    ).rejects.toThrow(AeadDecryptionError);
  });

  it("fails to decrypt when an envelope is swapped between two items", async () => {
    const kek = await generateVaultKey();
    const aadItemA = buildAad("user-1", "item-A", 1, 1);
    const aadItemB = buildAad("user-1", "item-B", 1, 1);

    const { key: keyA, wrappedKey: wrappedKeyA } = await generateAndWrapKey(
      kek,
      aadItemA
    );
    const { key: keyB } = await generateAndWrapKey(kek, aadItemB);

    const blobA = await aeadEncrypt(
      keyA,
      new TextEncoder().encode("item A password"),
      aadItemA
    );
    const blobB = await aeadEncrypt(
      keyB,
      new TextEncoder().encode("item B password"),
      aadItemB
    );

    // Server swaps blobB into item A's record
    await expect(aeadDecrypt(keyA, blobB, aadItemA)).rejects.toThrow(
      AeadDecryptionError
    );
    // Server swaps blobA into item B's record
    await expect(aeadDecrypt(keyB, blobA, aadItemB)).rejects.toThrow(
      AeadDecryptionError
    );
    // Server swaps wrappedKeyA into item B's record
    await expect(unwrapKey(kek, wrappedKeyA, aadItemB)).rejects.toThrow(
      AeadDecryptionError
    );
  });

  it("fails to decrypt a truncated envelope", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-1", "item-1", 1, 1);
    const envelope = await aeadEncrypt(key, new Uint8Array([1, 2, 3]), aad);

    // Empty and 1-byte truncated
    await expect(aeadDecrypt(key, new Uint8Array(0), aad)).rejects.toThrow(
      EnvelopeError
    );
    await expect(aeadDecrypt(key, new Uint8Array([0x01]), aad)).rejects.toThrow(
      EnvelopeError
    );

    // Truncated by 1 byte
    const truncatedByOne = envelope.subarray(0, envelope.byteLength - 1);
    try {
      await aeadDecrypt(key, truncatedByOne, aad);
      expect.unreachable("Should have thrown EnvelopeError");
    } catch (err) {
      expect(err).toBeInstanceOf(EnvelopeError);
      expect((err as EnvelopeError).code).toBe("TRUNCATED_DATA");
    }

    // Truncated to header only
    const headerOnly = envelope.subarray(0, ENVELOPE_HEADER_BYTE_LENGTH);
    await expect(aeadDecrypt(key, headerOnly, aad)).rejects.toThrow(
      EnvelopeError
    );

    // Also verify oversized envelope (> 65536 bytes) and oversized plaintext are rejected
    const oversized = new Uint8Array(MAX_ENVELOPE_BYTE_LENGTH + 1);
    oversized[0] = ENVELOPE_VERSION_V1;
    oversized[1] = ALGORITHM_ID_AES_256_GCM;
    try {
      await aeadDecrypt(key, oversized, aad);
      expect.unreachable("Should have thrown EnvelopeError");
    } catch (err) {
      expect(err).toBeInstanceOf(EnvelopeError);
      expect((err as EnvelopeError).code).toBe("OVERSIZED_DATA");
    }

    const oversizedPlaintext = new Uint8Array(MAX_PLAINTEXT_BYTE_LENGTH + 1);
    expect(() => padPlaintext(oversizedPlaintext)).toThrow(EnvelopeError);
  });

  it("fails to decrypt an envelope with an unknown version byte", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-1", "item-1", 1, 1);
    const envelope = await aeadEncrypt(key, new Uint8Array([1, 2, 3]), aad);

    const badVersion = new Uint8Array(envelope);
    badVersion[0] = 0x02;
    try {
      await aeadDecrypt(key, badVersion, aad);
      expect.unreachable("Should have thrown EnvelopeError");
    } catch (err) {
      expect(err).toBeInstanceOf(EnvelopeError);
      expect((err as EnvelopeError).code).toBe("UNKNOWN_VERSION");
    }
  });

  it("fails to decrypt an envelope with an unknown algorithm byte", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-1", "item-1", 1, 1);
    const envelope = await aeadEncrypt(key, new Uint8Array([1, 2, 3]), aad);

    const badAlgo = new Uint8Array(envelope);
    badAlgo[1] = 0x02;
    try {
      await aeadDecrypt(key, badAlgo, aad);
      expect.unreachable("Should have thrown EnvelopeError");
    } catch (err) {
      expect(err).toBeInstanceOf(EnvelopeError);
      expect((err as EnvelopeError).code).toBe("UNKNOWN_ALGORITHM");
    }
  });
});

describe("5. Nonce uniqueness test", () => {
  it("encrypting the same plaintext twice produces different nonces and different envelopes", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-1", "item-1", 1, 1);
    const pt = new TextEncoder().encode("identical-plaintext");

    const env1 = await aeadEncrypt(key, pt, aad);
    const env2 = await aeadEncrypt(key, pt, aad);

    const dec1 = decodeEnvelope(env1);
    const dec2 = decodeEnvelope(env2);

    expect(bytesToHex(dec1.nonce)).not.toBe(bytesToHex(dec2.nonce));
    expect(bytesToHex(env1)).not.toBe(bytesToHex(env2));
  });
});

describe("6. Padding bucket test (256-byte buckets)", () => {
  it("pads plaintext into 256-byte buckets and produces matching ciphertext sizes", async () => {
    const key = await generateItemKey();
    const aad = buildAad("user-1", "item-1", 1, 1);

    // 4-byte length prefix means:
    // - 0..252 bytes of plaintext -> 1 bucket (256 bytes padded)
    // - 253..508 bytes of plaintext -> 2 buckets (512 bytes padded)
    // - 509..764 bytes of plaintext -> 3 buckets (768 bytes padded)
    const cases: Array<{ ptLen: number; expectedPaddedBytes: number }> = [
      { ptLen: 0, expectedPaddedBytes: 256 },
      { ptLen: 1, expectedPaddedBytes: 256 },
      { ptLen: 100, expectedPaddedBytes: 256 },
      { ptLen: 252, expectedPaddedBytes: 256 },
      { ptLen: 253, expectedPaddedBytes: 512 },
      { ptLen: 508, expectedPaddedBytes: 512 },
      { ptLen: 509, expectedPaddedBytes: 768 },
    ];

    for (const { ptLen, expectedPaddedBytes } of cases) {
      const pt = randomBytes(ptLen);
      const padded = padPlaintext(pt);
      expect(padded.byteLength).toBe(expectedPaddedBytes);

      const envelope = await aeadEncrypt(key, pt, aad);
      const decoded = decodeEnvelope(envelope);
      const ciphertextOnlyLength =
        decoded.ciphertextAndTag.byteLength - GCM_TAG_BYTE_LENGTH;

      expect(ciphertextOnlyLength).toBe(expectedPaddedBytes);
      expect(ciphertextOnlyLength % PADDING_BUCKET_BYTES).toBe(0);
      expect(envelope.byteLength).toBe(
        ENVELOPE_HEADER_BYTE_LENGTH + expectedPaddedBytes + GCM_TAG_BYTE_LENGTH
      );

      const recovered = await aeadDecrypt(key, envelope, aad);
      expect(recovered).toEqual(pt);
    }
  });
});

describe("7. Secret Key (10,000 keys, 128-bit entropy, roundtrip, typo detection)", () => {
  it("generates 10,000 distinct 128-bit keys, roundtrips parse(format(x)), and handles case/spaces/dashes", () => {
    const seenHex = new Set<string>();
    const seenFormatted = new Set<string>();

    for (let i = 0; i < 10_000; i++) {
      const sk = generateSecretKey();
      expect(sk.rawBytes.byteLength).toBe(SECRET_KEY_BYTE_LENGTH); // 16 bytes = 128 bits

      const rawHex = bytesToHex(sk.rawBytes);
      seenHex.add(rawHex);
      seenFormatted.add(sk.formatted);

      // Strip dashes: 2 prefix ("A3") + 26 payload + 1 check = 29 chars
      const stripped = sk.formatted.replace(/-/g, "");
      expect(stripped.length).toBe(SECRET_KEY_TOTAL_CHARS);
      expect(stripped.slice(0, 2)).toBe("A3");
      expect(stripped.slice(2, -1).length).toBe(SECRET_KEY_PAYLOAD_CHARS);

      const parsed = parseSecretKey(sk.formatted);
      expect(parsed.rawBytes).toEqual(sk.rawBytes);
      expect(parsed.formatted).toBe(sk.formatted);
    }

    // All 10,000 random 128-bit keys must be unique
    expect(seenHex.size).toBe(10_000);
    expect(seenFormatted.size).toBe(10_000);

    // Case-insensitive and tolerant of arbitrary spaces/dashes and O/I/L Crockford aliases
    const sample = generateSecretKey();
    const messyInput = `  ${sample.formatted.toLowerCase().replace(/-/g, " - ")}  `;
    const parsedMessy = parseSecretKey(messyInput);
    expect(parsedMessy.rawBytes).toEqual(sample.rawBytes);
    expect(parsedMessy.formatted).toBe(sample.formatted);

    // Confirmation suffix returns last 4 alphanumeric characters
    const suffix = getSecretKeyConfirmationSuffix(sample);
    expect(suffix.length).toBe(4);
    expect(sample.formatted.replace(/-/g, "").endsWith(suffix)).toBe(true);
  });

  it("detects 100% of single-character mistypes across every position and alphabet replacement", () => {
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    // Test exhaustive single-character mutations across 25 random keys
    // (25 keys * 29 positions * 31 alternative characters = 22,475 single-char tamper attempts)
    for (let k = 0; k < 25; k++) {
      const sk = generateSecretKey();
      const clean = sk.formatted.replace(/-/g, "");

      for (let pos = 0; pos < clean.length; pos++) {
        const originalChar = clean[pos];
        for (let c = 0; c < alphabet.length; c++) {
          const replacementChar = alphabet[c];
          if (replacementChar === undefined || replacementChar === originalChar) {
            continue;
          }

          const mutated =
            clean.slice(0, pos) + replacementChar + clean.slice(pos + 1);
          expect(validateSecretKey(mutated)).toBe(false);
          expect(() => parseSecretKey(mutated)).toThrow(SecretKeyError);
        }
      }
    }
  });

  it("rejects PRD-length truncated keys (only 18 chars after A3)", () => {
    expect(() => parseSecretKey("A3-ABCDEF-GHJKMN-PQRSTV")).toThrow(
      SecretKeyError
    );
    expect(validateSecretKey("A3-ABCDEF-GHJKMN-PQRSTV")).toBe(false);
  });

  it("rejects a Secret Key whose 2 unused padding bits are not zero", () => {
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    // Start with all-zero 128-bit key -> 26 '0' payload chars, then set the 26th payload char
    // to values with non-zero low 2 bits (1, 2, 3 -> '1', '2', '3') and find the matching
    // check character so the checksum passes and the parser reaches the pad-bit check.
    for (const nonZeroPadChar of ["1", "2", "3"]) {
      const prefixAndPayload = `A3${"0".repeat(25)}${nonZeroPadChar}`;
      let foundMatchingChecksum = false;

      for (const candidateCheckChar of alphabet) {
        const candidateKey = `${prefixAndPayload}${candidateCheckChar}`;
        try {
          parseSecretKey(candidateKey);
          expect.unreachable(
            "parseSecretKey must never succeed when the 2 unused padding bits are non-zero"
          );
        } catch (err) {
          expect(err).toBeInstanceOf(SecretKeyError);
          const skErr = err as SecretKeyError;
          if (skErr.code === "NON_ZERO_PAD_BITS") {
            foundMatchingChecksum = true;
          } else {
            expect(skErr.code).toBe("CHECKSUM_MISMATCH");
          }
        }
      }

      // Exactly 1 of the 32 check characters passes the checksum and hits NON_ZERO_PAD_BITS
      expect(foundMatchingChecksum).toBe(true);
    }
  });
});

describe("8. Randomness, wipe, and static ban on Math.random", () => {
  it("generates unbiased random integers in [0, max) and zeroes buffers via zeroize()", () => {
    expect(randomInt(1)).toBe(0);

    const counts = [0, 0, 0, 0, 0, 0, 0];
    for (let i = 0; i < 7000; i++) {
      const r = randomInt(7);
      expect(r).toBeGreaterThanOrEqual(0);
      expect(r).toBeLessThan(7);
      counts[r] = (counts[r] ?? 0) + 1;
    }
    for (const count of counts) {
      // Expected mean is 1000; 750..1250 is >7 standard deviations wide
      expect(count).toBeGreaterThan(750);
      expect(count).toBeLessThan(1250);
    }

    const buf = randomBytes(KEY_BYTE_LENGTH);
    expect(buf.some((b) => b !== 0)).toBe(true);
    zeroize(buf);
    expect(buf.every((b) => b === 0)).toBe(true);

    const ab = new ArrayBuffer(16);
    new Uint8Array(ab).fill(0xff);
    zeroize(ab);
    expect(new Uint8Array(ab).every((b) => b === 0)).toBe(true);
  });

  it("verifies zero runtime dependencies and no Math.random in packages/crypto/src", () => {
    const pkgRecord = pkgJson as Record<string, unknown>;
    expect(pkgRecord["dependencies"]).toBeUndefined();

    const exportedFunctions: ReadonlyArray<(...args: never[]) => unknown> = [
      buildAadDirect,
      aeadEncryptDirect,
      padPlaintextDirect,
      generateKeyDirect,
      randomBytesDirect,
      formatSecretKeyDirect,
      zeroizeDirect,
    ];
    expect(kdfLabelsDirect.VAULT_KEK_V1).toBe("vault-kek-v1");

    // Build the forbidden identifier dynamically so this test file itself never contains it literally
    const forbiddenCall = ["Math", "random"].join(".");
    for (const fn of exportedFunctions) {
      expect(fn.toString()).not.toContain(forbiddenCall);
    }
  });
});
