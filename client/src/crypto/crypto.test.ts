import * as cryptoPublicApi from './index.ts';
import {
  AAD_PURPOSES,
  AES_256_KEY_BITS,
  AES_256_KEY_BYTES,
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BITS,
  AES_GCM_TAG_BYTES,
  type AadParams,
  type AadPurpose,
  CryptoArgumentError,
  DECRYPTION_ERROR_MESSAGE,
  DecryptionError,
  ENVELOPE_HEADER_BYTES,
  ENVELOPE_OVERHEAD_BYTES,
  ENVELOPE_VERSION_V1,
  INVALID_SECRET_KEY_MESSAGE,
  InvalidSecretKeyError,
  type ItemAadContext,
  MAX_AAD_ID_BYTES,
  MAX_ENCRYPTED_ENVELOPE_BYTES,
  MAX_PLAINTEXT_BYTES,
  MAX_SECRET_KEY_INPUT_LENGTH,
  PADDING_BUCKET_BYTES,
  PADDING_LENGTH_PREFIX_BYTES,
  PASSWORD_INPUT_BYTES,
  PASSWORD_INPUT_INFO,
  SECRET_KEY_BASE32_ALPHABET,
  SECRET_KEY_BASE32_CHARS,
  SECRET_KEY_BYTES,
  SECRET_KEY_PREFIX,
  VAULT_KEK_INFO,
  WRAPPED_KEY_ENVELOPE_BYTES,
  assertValidKeyUsages,
  constantTimeEqual,
  createAndWrapVaultKey,
  decodeEnvelope,
  decrypt,
  decryptItem,
  decryptItemMetadata,
  decryptItemSecret,
  deriveKek,
  derivePasswordInput,
  encodeAad,
  encrypt,
  encryptItem,
  formatSecretKey,
  generateSecretKey,
  getWebCrypto,
  hkdf,
  maxPaddedBytesForOverhead,
  padToBucket,
  parseSecretKey,
  rewrapKey,
  secureRandom,
  toArrayBuffer,
  unpadFromBucket,
  unwrapKey,
  wipeBuffer,
  wipeBuffers,
  wrapKey,
} from './index.ts';
import { generateAesGcmKey, importAesGcmKey } from './aesGcm.ts';
import { encodeEnvelope } from './envelope.ts';

interface NodeGcmCipher {
  setAAD(buffer: Uint8Array): this;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
  getAuthTag(): Uint8Array;
}

interface NodeGcmDecipher {
  setAAD(buffer: Uint8Array): this;
  setAuthTag(buffer: Uint8Array): this;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
}

interface NodeCryptoBuiltin {
  createCipheriv(
    algorithm: 'aes-256-gcm',
    key: Uint8Array,
    iv: Uint8Array,
  ): NodeGcmCipher;
  createDecipheriv(
    algorithm: 'aes-256-gcm',
    key: Uint8Array,
    iv: Uint8Array,
  ): NodeGcmDecipher;
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertBytesEqual(
  actual: Uint8Array,
  expected: Uint8Array,
  message: string,
): void {
  if (!constantTimeEqual(actual, expected)) {
    throw new Error(
      `Assertion failed (${message}): byte mismatch (actual len=${actual.byteLength}, expected len=${expected.byteLength})`,
    );
  }
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.byteLength; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    out += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  }
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i] ?? 0);
  }
  return btoa(binary);
}

function bytesToBase32(bytes: Uint8Array): string {
  let bitBuffer = 0;
  let bitCount = 0;
  let out = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    bitBuffer = (bitBuffer << 8) | (bytes[i] ?? 0);
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      const idx = (bitBuffer >> bitCount) & 0x1f;
      out += SECRET_KEY_BASE32_ALPHABET[idx] ?? '';
      bitBuffer &= (1 << bitCount) - 1;
    }
  }
  if (bitCount > 0) {
    const idx = (bitBuffer << (5 - bitCount)) & 0x1f;
    out += SECRET_KEY_BASE32_ALPHABET[idx] ?? '';
  }
  return out;
}

function concatBytes(...arrays: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const arr of arrays) {
    total += arr.byteLength;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.byteLength;
  }
  return out;
}

function makeAadForPurpose(
  purpose: AadPurpose,
  overrides?: Partial<{
    readonly userId: string | Uint8Array;
    readonly itemId: string | Uint8Array;
    readonly credentialId: string | Uint8Array;
    readonly keyVersion: number;
    readonly schemaVersion: number;
    readonly revision: number;
  }>,
): AadParams {
  const userId = overrides?.userId ?? 'user-1111-2222';
  const keyVersion = overrides?.keyVersion ?? 1;
  const schemaVersion = overrides?.schemaVersion ?? 1;

  if (purpose === 'vault-key-ks-prf') {
    const credentialId = overrides?.credentialId ?? 'cred-passkey-9999';
    return overrides?.revision !== undefined
      ? {
          purpose,
          userId,
          credentialId,
          keyVersion,
          schemaVersion,
          revision: overrides.revision,
        }
      : {
          purpose,
          userId,
          credentialId,
          keyVersion,
          schemaVersion,
        };
  }

  if (purpose === 'vault-key-km' || purpose === 'vault-key-ks-master') {
    return {
      purpose,
      userId,
      ...(overrides?.itemId !== undefined ? { itemId: overrides.itemId } : {}),
      keyVersion,
      schemaVersion,
      ...(overrides?.revision !== undefined
        ? { revision: overrides.revision }
        : {}),
    };
  }

  return {
    purpose,
    userId,
    itemId: overrides?.itemId ?? 'item-3333-4444',
    keyVersion,
    schemaVersion,
    revision: overrides?.revision ?? 1,
  };
}

async function assertRejectsWithDecryptionError(
  fn: () => Promise<unknown>,
  context: string,
): Promise<DecryptionError> {
  let caught: unknown;
  try {
    await fn();
  } catch (err: unknown) {
    caught = err;
  }
  assert(
    caught instanceof DecryptionError,
    `${context}: expected DecryptionError`,
  );
  const decErr = caught as DecryptionError;
  assert(
    decErr.message === DECRYPTION_ERROR_MESSAGE,
    `${context}: expected uniform message "${DECRYPTION_ERROR_MESSAGE}"`,
  );
  assert(
    decErr.cause === undefined,
    `${context}: DecryptionError must not attach cause`,
  );
  return decErr;
}

function assertThrowsDecryptionErrorSync(
  fn: () => unknown,
  context: string,
): void {
  let caught: unknown;
  try {
    fn();
  } catch (err: unknown) {
    caught = err;
  }
  assert(
    caught instanceof DecryptionError,
    `${context}: expected DecryptionError`,
  );
  const decErr = caught as DecryptionError;
  assert(
    decErr.message === DECRYPTION_ERROR_MESSAGE,
    `${context}: expected uniform message "${DECRYPTION_ERROR_MESSAGE}"`,
  );
}

function assertThrowsCryptoArgumentErrorSync(
  fn: () => unknown,
  context: string,
): void {
  let caught: unknown;
  try {
    fn();
  } catch (err: unknown) {
    caught = err;
  }
  assert(
    caught instanceof CryptoArgumentError,
    `${context}: expected CryptoArgumentError`,
  );
}

async function assertRejectsWithCryptoArgumentError(
  fn: () => Promise<unknown>,
  context: string,
): Promise<void> {
  let caught: unknown;
  try {
    await fn();
  } catch (err: unknown) {
    caught = err;
  }
  assert(
    caught instanceof CryptoArgumentError,
    `${context}: expected CryptoArgumentError`,
  );
}

/**
 * 1. RFC 5869 HKDF-SHA-256 Known-Answer Vectors (Appendix A.1, A.2, A.3),
 *    `derivePasswordInput` (NFKC + 16B Secret Key salt), and `deriveKek`.
 */
async function testRfc5869HkdfAndKeyDerivations(): Promise<void> {
  // RFC 5869 A.1 - Test Case 1: Basic test case with SHA-256
  const tc1Ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const tc1Salt = hexToBytes('000102030405060708090a0b0c');
  const tc1Info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
  const tc1ExpectedOkm = hexToBytes(
    '3cb25f25faacd57a90434f64d0362f2a' +
      '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
      '34007208d5b887185865',
  );
  const tc1Okm = await hkdf(tc1Ikm, tc1Salt, tc1Info, 42);
  assertBytesEqual(tc1Okm, tc1ExpectedOkm, 'RFC 5869 Test Case 1');

  // RFC 5869 A.2 - Test Case 2: SHA-256 with longer inputs/outputs
  const tc2Ikm = hexToBytes(
    '000102030405060708090a0b0c0d0e0f' +
      '101112131415161718191a1b1c1d1e1f' +
      '202112232425262728292a2b2c2d2e2f'.replace('202112', '202122') +
      '303132333435363738393a3b3c3d3e3f' +
      '404142434445464748494a4b4c4d4e4f',
  );
  const tc2Salt = hexToBytes(
    '606162636465666768696a6b6c6d6e6f' +
      '707172737475767778797a7b7c7d7e7f' +
      '808182838485868788898a8b8c8d8e8f' +
      '909192939495969798999a9b9c9d9e9f' +
      'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
  );
  const tc2Info = hexToBytes(
    'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
      'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
      'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
      'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
      'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
  );
  const tc2ExpectedOkm = hexToBytes(
    'b11e398dc80327a1c8e7f78c596a4934' +
      '4f012eda2d4efad8a050cc4c19afa97c' +
      '59045a99cac7827271cb41c65e590e09' +
      'da3275600c2f09b8367793a9aca3db71' +
      'cc30c58179ec3e87c14c01d5c1f3434f' +
      '1d87',
  );
  const tc2Okm = await hkdf(tc2Ikm, tc2Salt, tc2Info, 82);
  assertBytesEqual(tc2Okm, tc2ExpectedOkm, 'RFC 5869 Test Case 2');

  // RFC 5869 A.3 - Test Case 3: SHA-256 with zero-length salt and info
  const tc3Ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const tc3Salt = new Uint8Array(0);
  const tc3Info = new Uint8Array(0);
  const tc3ExpectedOkm = hexToBytes(
    '8da4e775a563c18f715f802a063c5a31' +
      'b8a11f5c5ee1879ec3454e5f3c738d2d' +
      '9d201395faa4b61a96c8',
  );
  const tc3Okm = await hkdf(tc3Ikm, tc3Salt, tc3Info, 42);
  assertBytesEqual(tc3Okm, tc3ExpectedOkm, 'RFC 5869 Test Case 3');

  // Verify derivePasswordInput: HKDF-SHA-256(NFKC(password), rawSecretKey16B, "strongroom-pw-input-v1", 32)
  const formattedSecretKey = generateSecretKey();
  const rawSecretKey16B = parseSecretKey(formattedSecretKey);
  assert(
    rawSecretKey16B.byteLength === SECRET_KEY_BYTES,
    'parseSecretKey returns exactly 16 raw bytes',
  );

  // Composed vs decomposed Unicode password strings must normalize to identical NFKC bytes
  const pwComposed = 'Str\u00f6ngR\u00f4\u00f6m-Passw\u00f6rd-2026!';
  const pwDecomposed = 'Stro\u0308ngRo\u0302o\u0308m-Passwo\u0308rd-2026!';
  const pwInput1 = await derivePasswordInput(pwComposed, rawSecretKey16B);
  const pwInput2 = await derivePasswordInput(pwDecomposed, rawSecretKey16B);
  assert(
    pwInput1.byteLength === PASSWORD_INPUT_BYTES,
    'derivePasswordInput returns 32 bytes',
  );
  assertBytesEqual(
    pwInput1,
    pwInput2,
    'derivePasswordInput NFKC-normalizes master password',
  );

  const expectedPwInput = await hkdf(
    new TextEncoder().encode(pwComposed.normalize('NFKC')),
    rawSecretKey16B,
    new TextEncoder().encode(PASSWORD_INPUT_INFO),
    PASSWORD_INPUT_BYTES,
  );
  assertBytesEqual(
    pwInput1,
    expectedPwInput,
    'derivePasswordInput matches HKDF-SHA-256 specification',
  );

  await assertRejectsWithCryptoArgumentError(
    () => derivePasswordInput('', rawSecretKey16B),
    'derivePasswordInput rejects empty password',
  );
  const formattedKeyBytes = new TextEncoder().encode(formattedSecretKey);
  await assertRejectsWithCryptoArgumentError(
    () => derivePasswordInput(pwComposed, formattedKeyBytes),
    'derivePasswordInput rejects 34-byte formatted Secret Key string bytes',
  );

  // Confirm deriveKek uses the 16 raw bytes from parseSecretKey and only grants ['wrapKey', 'unwrapKey']
  const exportKey = secureRandom(32);
  const kek = await deriveKek(exportKey, rawSecretKey16B);
  assert(kek.extractable === false, 'KEK must be non-extractable');
  assert(
    kek.usages.length === 2 &&
      kek.usages.includes('wrapKey') &&
      kek.usages.includes('unwrapKey') &&
      !kek.usages.includes('encrypt') &&
      !kek.usages.includes('decrypt'),
    'KEK must have ONLY wrapKey and unwrapKey usages',
  );

  // Verify deriveKek matches HKDF(exportKey, rawSecretKey16B, "vault-kek-v1", 32) by wrapping/unwrapping
  const rawKekBytes = await hkdf(
    exportKey,
    rawSecretKey16B,
    new TextEncoder().encode(VAULT_KEK_INFO),
    32,
  );
  const importedKek = await importAesGcmKey(rawKekBytes, [
    'wrapKey',
    'unwrapKey',
  ]);
  const kmAad = makeAadForPurpose('vault-key-km');
  const rawLeafKey = secureRandom(32);
  const wrappedByKek = await wrapKey(kek, rawLeafKey, kmAad);
  const unwrappedByImportedKek = await unwrapKey(
    importedKek,
    wrappedByKek,
    kmAad,
    ['wrapKey', 'unwrapKey'],
  );
  assert(
    unwrappedByImportedKek.extractable === false,
    'Key unwrapped by imported KEK matches KEK derivation',
  );

  await assertRejectsWithCryptoArgumentError(
    () => deriveKek(exportKey, formattedKeyBytes),
    'deriveKek must reject non-16-byte formatted Secret Key string bytes',
  );

  wipeBuffers(
    exportKey,
    rawSecretKey16B,
    rawKekBytes,
    formattedKeyBytes,
    rawLeafKey,
    pwInput1,
    pwInput2,
    expectedPwInput,
  );
}

/**
 * 2. Official AES-256-GCM Known-Answer Test Vectors & Cross-Implementation
 *    Differential Test against `node:crypto`.
 *
 * Exact citation for Known-Answer Test Vectors:
 *   David A. McGrew and John Viega, "The Galois/Counter Mode of Operation (GCM)",
 *   NIST Modes of Operation Submission / IEEE P802.1AE, May 2005, Appendix B,
 *   Test Cases 13, 14, 15, and 16 (256-bit key, 96-bit IV, 128-bit tag).
 */
async function testAes256GcmKnownAnswerAndNodeCrypto(): Promise<void> {
  const vectors: ReadonlyArray<{
    readonly name: string;
    readonly keyHex: string;
    readonly ivHex: string;
    readonly ptHex: string;
    readonly aadHex: string;
    readonly ctHex: string;
    readonly tagHex: string;
  }> = [
    {
      name: 'McGrew & Viega GCM Spec Appendix B - Test Case 13 (256-bit zero key, empty PT, empty AAD)',
      keyHex:
        '0000000000000000000000000000000000000000000000000000000000000000',
      ivHex: '000000000000000000000000',
      ptHex: '',
      aadHex: '',
      ctHex: '',
      tagHex: '530f8afbc74536b9a963b4f1c4cb738b',
    },
    {
      name: 'McGrew & Viega GCM Spec Appendix B - Test Case 14 (256-bit zero key, 16B zero PT, empty AAD)',
      keyHex:
        '0000000000000000000000000000000000000000000000000000000000000000',
      ivHex: '000000000000000000000000',
      ptHex: '00000000000000000000000000000000',
      aadHex: '',
      ctHex: 'cea7403d4d606b6e074ec5d3baf39d18',
      tagHex: 'd0d1c8a799996bf0265b98b5d48ab919',
    },
    {
      name: 'McGrew & Viega GCM Spec Appendix B - Test Case 15 (256-bit key, 64B PT, empty AAD)',
      keyHex:
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
      ivHex: 'cafebabefacedbaddecaf888',
      ptHex:
        'd9313225f88406e5a55909c5aff5269a' +
        '86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525' +
        'b16aedf5aa0de657ba637b391aafd255',
      aadHex: '',
      ctHex:
        '522dc1f099567d07f47f37a32a84427d' +
        '643a8cdcbfe5c0c97598a2bd2555d1aa' +
        '8cb08e48590dbb3da7b08b1056828838' +
        'c5f61e6393ba7a0abcc9f662898015ad',
      tagHex: 'b094dac5d93471bdec1a502270e3cc6c',
    },
    {
      name: 'McGrew & Viega GCM Spec Appendix B - Test Case 16 (256-bit key, 60B PT, 20B AAD)',
      keyHex:
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
      ivHex: 'cafebabefacedbaddecaf888',
      ptHex:
        'd9313225f88406e5a55909c5aff5269a' +
        '86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525' +
        'b16aedf5aa0de657ba637b39',
      aadHex: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
      ctHex:
        '522dc1f099567d07f47f37a32a84427d' +
        '643a8cdcbfe5c0c97598a2bd2555d1aa' +
        '8cb08e48590dbb3da7b08b1056828838' +
        'c5f61e6393ba7a0abcc9f662',
      tagHex: '76fc6ece0f4e1768cddf8853bb2d551b',
    },
  ];

  const webCrypto = getWebCrypto();
  for (const vec of vectors) {
    const rawKey = hexToBytes(vec.keyHex);
    const iv = hexToBytes(vec.ivHex);
    const pt = hexToBytes(vec.ptHex);
    const aad = hexToBytes(vec.aadHex);
    const expectedCtWithTag = concatBytes(
      hexToBytes(vec.ctHex),
      hexToBytes(vec.tagHex),
    );

    const cryptoKey = await importAesGcmKey(rawKey, ['encrypt', 'decrypt']);
    const encryptedBuf = await webCrypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(iv),
        additionalData: toArrayBuffer(aad),
        tagLength: AES_GCM_TAG_BITS,
      },
      cryptoKey,
      toArrayBuffer(pt),
    );
    assertBytesEqual(
      new Uint8Array(encryptedBuf),
      expectedCtWithTag,
      `${vec.name} encrypt`,
    );

    const env = encodeEnvelope(
      iv,
      new Uint8Array(encryptedBuf),
      ENVELOPE_VERSION_V1,
    );
    const decoded = decodeEnvelope(env);
    const decryptedBuf = await webCrypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(decoded.nonce),
        additionalData: toArrayBuffer(aad),
        tagLength: AES_GCM_TAG_BITS,
      },
      cryptoKey,
      toArrayBuffer(decoded.ciphertextWithTag),
    );
    assertBytesEqual(
      new Uint8Array(decryptedBuf),
      pt,
      `${vec.name} decrypt`,
    );
  }

  // Differential test: compare our `encrypt` and `decrypt` against `node:crypto` for random inputs
  const nodeCryptoModuleSpecifier: string = 'node:crypto';
  const nodeCrypto = (await import(
    /* @vite-ignore */ nodeCryptoModuleSpecifier
  )) as unknown as NodeCryptoBuiltin;

  for (const ptLen of [0, 1, 17, 64, 223, 224, 511, 1024]) {
    const rawKey = secureRandom(AES_256_KEY_BYTES);
    const pt = secureRandom(ptLen);
    const aadParams = makeAadForPurpose('item-secret', {
      userId: `user-${ptLen}`,
      itemId: `item-${ptLen}`,
      keyVersion: 3,
      schemaVersion: 2,
      revision: 5,
    });
    const aadBytes = encodeAad(aadParams);

    const key = await importAesGcmKey(rawKey, ['encrypt', 'decrypt']);
    const envelope = await encrypt(key, pt, aadParams);

    assert(
      envelope[0] === ENVELOPE_VERSION_V1,
      `Envelope version is 0x01 for length ${ptLen}`,
    );
    const nonce = envelope.subarray(1, 1 + AES_GCM_NONCE_BYTES);
    const ctBody = envelope.subarray(
      ENVELOPE_HEADER_BYTES,
      envelope.byteLength - AES_GCM_TAG_BYTES,
    );
    const tag = envelope.subarray(envelope.byteLength - AES_GCM_TAG_BYTES);

    // Re-compute ciphertext and tag with node:crypto using the same key, nonce, AAD, and padded plaintext
    const expectedPadded = padToBucket(pt, ENVELOPE_OVERHEAD_BYTES);
    const cipher = nodeCrypto.createCipheriv('aes-256-gcm', rawKey, nonce);
    cipher.setAAD(aadBytes);
    const nodeCt = concatBytes(
      cipher.update(expectedPadded),
      cipher.final(),
    );
    const nodeTag = cipher.getAuthTag();

    assertBytesEqual(
      ctBody,
      nodeCt,
      `encrypt() ciphertext matches node:crypto for ${ptLen}B`,
    );
    assertBytesEqual(
      tag,
      nodeTag,
      `encrypt() GCM auth tag matches node:crypto for ${ptLen}B`,
    );

    // Also decrypt our envelope with node:crypto and unpad
    const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', rawKey, nonce);
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(tag);
    const nodeDecryptedPadded = concatBytes(
      decipher.update(ctBody),
      decipher.final(),
    );
    const nodeUnpadded = unpadFromBucket(
      nodeDecryptedPadded,
      ENVELOPE_OVERHEAD_BYTES,
    );
    assertBytesEqual(
      nodeUnpadded,
      pt,
      `node:crypto decrypts our encrypt() output for ${ptLen}B`,
    );

    wipeBuffers(rawKey, pt, aadBytes, expectedPadded, nodeDecryptedPadded, nodeUnpadded);
  }
}

/**
 * 3. Key Usage Enforcement, Non-Extractability, and Public API Hygiene Tests
 *    (Requirement A & D.2).
 */
async function testKeyUsagesAndNonExtractability(): Promise<void> {
  // Public index.ts must NOT export encodeEnvelope, generateAesGcmKey, importAesGcmKey, or resolveAadBytes
  const exportedNames = Object.keys(cryptoPublicApi);
  assert(
    !exportedNames.includes('encodeEnvelope'),
    'index.ts must not export encodeEnvelope',
  );
  assert(
    !exportedNames.includes('generateAesGcmKey'),
    'index.ts must not export generateAesGcmKey',
  );
  assert(
    !exportedNames.includes('importAesGcmKey'),
    'index.ts must not export importAesGcmKey',
  );
  assert(
    !exportedNames.includes('resolveAadBytes'),
    'index.ts must not export resolveAadBytes',
  );

  // Mixing wrapping usages and data usages must throw CryptoArgumentError everywhere
  const mixedUsageSets: ReadonlyArray<ReadonlyArray<KeyUsage>> = [
    ['encrypt', 'wrapKey'],
    ['decrypt', 'unwrapKey'],
    ['encrypt', 'decrypt', 'wrapKey'],
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    ['sign' as KeyUsage],
    [],
  ];

  const rawKey = secureRandom(AES_256_KEY_BYTES);
  const wrappingKey = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const kmAad = makeAadForPurpose('vault-key-km');
  const validWrappedKm = await wrapKey(wrappingKey, rawKey, kmAad);

  for (const badUsages of mixedUsageSets) {
    assertThrowsCryptoArgumentErrorSync(
      () => assertValidKeyUsages(badUsages),
      `assertValidKeyUsages rejects [${badUsages.join(',')}]`,
    );
    await assertRejectsWithCryptoArgumentError(
      () => generateAesGcmKey(badUsages),
      `generateAesGcmKey rejects [${badUsages.join(',')}]`,
    );
    await assertRejectsWithCryptoArgumentError(
      () => importAesGcmKey(rawKey, badUsages),
      `importAesGcmKey rejects [${badUsages.join(',')}]`,
    );
    await assertRejectsWithCryptoArgumentError(
      () => createAndWrapVaultKey(wrappingKey, kmAad, badUsages),
      `createAndWrapVaultKey rejects [${badUsages.join(',')}]`,
    );
    await assertRejectsWithCryptoArgumentError(
      () => unwrapKey(wrappingKey, validWrappedKm, kmAad, badUsages),
      `unwrapKey rejects [${badUsages.join(',')}]`,
    );
  }

  // Derive KEK and create K_m and K_s
  const exportKey = secureRandom(32);
  const secretKey16B = secureRandom(16);
  const kek = await deriveKek(exportKey, secretKey16B);
  const { key: km, wrappedKey: wrappedKm } = await createAndWrapVaultKey(
    kek,
    makeAadForPurpose('vault-key-km'),
  );
  const { key: ks, wrappedKey: wrappedKs } = await createAndWrapVaultKey(
    kek,
    makeAadForPurpose('vault-key-ks-master'),
  );
  const leafKey = await generateAesGcmKey(['encrypt', 'decrypt']);

  // Verify subtle.exportKey rejects on KEK, K_m, K_s, and leafKey
  const webCrypto = getWebCrypto();
  for (const [label, k] of [
    ['KEK', kek],
    ['K_m', km],
    ['K_s', ks],
    ['leafKey', leafKey],
  ] as const) {
    let exportRejected = false;
    try {
      await webCrypto.subtle.exportKey('raw', k);
    } catch {
      exportRejected = true;
    }
    assert(exportRejected, `subtle.exportKey('raw') must reject on ${label}`);
  }

  // Verify subtle.decrypt and decrypt() with KEK, K_m, or K_s MUST reject
  // (prevents extracting wrapped key bytes by passing wrappedKey envelope to subtle.decrypt)
  const decodedKm = decodeEnvelope(wrappedKm);
  const kmAadBytes = encodeAad(makeAadForPurpose('vault-key-km'));
  for (const [label, wk] of [
    ['KEK', kek],
    ['K_m', km],
    ['K_s', ks],
  ] as const) {
    let subtleDecryptRejected = false;
    try {
      await webCrypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: toArrayBuffer(decodedKm.nonce),
          additionalData: toArrayBuffer(kmAadBytes),
          tagLength: AES_GCM_TAG_BITS,
        },
        wk,
        toArrayBuffer(decodedKm.ciphertextWithTag),
      );
    } catch {
      subtleDecryptRejected = true;
    }
    assert(
      subtleDecryptRejected,
      `subtle.decrypt with wrapping key ${label} must reject`,
    );

    await assertRejectsWithCryptoArgumentError(
      () => encrypt(wk, new Uint8Array([1, 2, 3]), makeAadForPurpose('item-meta')),
      `encrypt() with wrapping key ${label} must reject`,
    );
  }

  // Verify a leaf data key cannot wrapKey or unwrapKey
  await assertRejectsWithCryptoArgumentError(
    () => wrapKey(leafKey, rawKey, makeAadForPurpose('item-key-m')),
    'wrapKey with leaf data key must throw CryptoArgumentError',
  );
  await assertRejectsWithDecryptionError(
    () => unwrapKey(leafKey, wrappedKs, makeAadForPurpose('vault-key-ks-master')),
    'unwrapKey with leaf data key must throw DecryptionError',
  );
  let subtleWrapWithLeafRejected = false;
  const exportableProbe = await webCrypto.subtle.generateKey(
    { name: 'AES-GCM', length: AES_256_KEY_BITS },
    true,
    ['encrypt'],
  );
  try {
    await webCrypto.subtle.wrapKey(
      'raw',
      exportableProbe,
      leafKey,
      { name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 },
    );
  } catch {
    subtleWrapWithLeafRejected = true;
  }
  assert(
    subtleWrapWithLeafRejected,
    'subtle.wrapKey with leaf data key must reject',
  );

  // Verify wrapKey rejects a CryptoKey passed as keyToWrap (compile-time and runtime)
  await assertRejectsWithCryptoArgumentError(
    // @ts-expect-error -- wrapKey only accepts Uint8Array for keyToWrap, never CryptoKey
    () => wrapKey(kek, leafKey, kmAad),
    'wrapKey must reject CryptoKey as keyToWrap',
  );

  wipeBuffers(rawKey, exportKey, secretKey16B, kmAadBytes);
}

/**
 * 4. Round-Trip, Normalization, Re-Wrapping (`rewrapKey`), and Padding Bounds Tests.
 */
async function testRoundTripsRewrapAndPadding(): Promise<void> {
  // secureRandom boundary lengths including > 65536 chunking
  const r0 = secureRandom(0);
  assert(r0.byteLength === 0, 'secureRandom(0) length');
  const r32 = secureRandom(32);
  assert(r32.byteLength === 32, 'secureRandom(32) length');
  const rLarge = secureRandom(70_000);
  assert(rLarge.byteLength === 70_000, 'secureRandom(70000) length');
  wipeBuffers(r32, rLarge);

  // constantTimeEqual rejects non-Uint8Array inputs
  assertThrowsCryptoArgumentErrorSync(
    // @ts-expect-error -- testing non-Uint8Array rejection
    () => constantTimeEqual('not-bytes', 'not-bytes'),
    'constantTimeEqual rejects strings',
  );
  assertThrowsCryptoArgumentErrorSync(
    // @ts-expect-error -- testing non-Uint8Array rejection
    () => constantTimeEqual({}, {}),
    'constantTimeEqual rejects plain objects',
  );

  // maxPaddedBytesForOverhead validates overheadBytes
  for (const badOverhead of [-1, 256, 1000, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assertThrowsCryptoArgumentErrorSync(
      () => maxPaddedBytesForOverhead(badOverhead),
      `maxPaddedBytesForOverhead rejects invalid overhead ${String(badOverhead)}`,
    );
  }

  // Secret Key round-trip, lowercase acceptance, hyphen/whitespace stripping,
  // >128-char rejection before regex, and intact "A3" prefix enforcement
  const rawSecret = secureRandom(SECRET_KEY_BYTES);
  const formatted = formatSecretKey(rawSecret);
  assert(formatted.startsWith('A3-'), 'Secret Key starts with A3-');

  const parsedCanonical = parseSecretKey(formatted);
  assertBytesEqual(parsedCanonical, rawSecret, 'Canonical Secret Key round-trip');

  const parsedLowercase = parseSecretKey(formatted.toLowerCase());
  assertBytesEqual(parsedLowercase, rawSecret, 'Lowercase Secret Key round-trip');

  const parsedNoHyphensAndSpaces = parseSecretKey(
    `  \t\n ${formatted.replace(/-/g, ' ').toLowerCase()} -- \r\n `,
  );
  assertBytesEqual(
    parsedNoHyphensAndSpaces,
    rawSecret,
    'Whitespace and hyphen stripped Secret Key round-trip',
  );

  // Reject > 128 chars before any regex, split prefix "A-3", leading hyphen "-A3", wrong lengths
  const over128Chars = `${' '.repeat(MAX_SECRET_KEY_INPUT_LENGTH)}${formatted}`;
  const splitPrefixHyphen = `A-3-${formatted.slice(3)}`;
  const splitPrefixSpace = `A 3-${formatted.slice(3)}`;
  const leadingHyphen = `-${formatted}`;
  for (const invalidInput of [
    '',
    'A3-',
    formatted.slice(0, -1),
    `${formatted}A`,
    `${formatted}-AAAAA`,
    over128Chars,
    splitPrefixHyphen,
    splitPrefixSpace,
    leadingHyphen,
  ]) {
    let threw = false;
    try {
      parseSecretKey(invalidInput);
    } catch (err: unknown) {
      threw =
        err instanceof InvalidSecretKeyError &&
        err.message === INVALID_SECRET_KEY_MESSAGE;
    }
    assert(threw, 'parseSecretKey must reject invalid input');
  }

  wipeBuffers(
    rawSecret,
    parsedCanonical,
    parsedLowercase,
    parsedNoHyphensAndSpaces,
  );

  // 256-byte bucket padding round-trips and 1 MiB ceiling validation
  for (const len of [0, 1, 15, 222, 223, 224, 251, 252, 253, 255, 256, 512, 1024]) {
    const sample = secureRandom(len);
    const paddedDirect = padToBucket(sample, 0);
    assert(
      paddedDirect.byteLength % PADDING_BUCKET_BYTES === 0,
      `Direct padded length for ${len} is a multiple of 256`,
    );
    const unpaddedDirect = unpadFromBucket(paddedDirect, 0);
    assertBytesEqual(
      unpaddedDirect,
      sample,
      `Direct pad/unpad round-trip for length ${len}`,
    );

    const paddedWithOverhead = padToBucket(sample, ENVELOPE_OVERHEAD_BYTES);
    assert(
      (paddedWithOverhead.byteLength + ENVELOPE_OVERHEAD_BYTES) %
        PADDING_BUCKET_BYTES ===
        0,
      `Envelope-adjusted padded length for ${len} aligns total envelope to 256`,
    );
    const unpaddedWithOverhead = unpadFromBucket(
      paddedWithOverhead,
      ENVELOPE_OVERHEAD_BYTES,
    );
    assertBytesEqual(
      unpaddedWithOverhead,
      sample,
      `Envelope-adjusted pad/unpad round-trip for length ${len}`,
    );
    wipeBuffers(
      sample,
      paddedDirect,
      unpaddedDirect,
      paddedWithOverhead,
      unpaddedWithOverhead,
    );
  }

  // Exact 1 MiB plaintext succeeds in padToBucket / unpadFromBucket
  const maxPlaintext = new Uint8Array(MAX_PLAINTEXT_BYTES);
  maxPlaintext[0] = 0xaa;
  maxPlaintext[MAX_PLAINTEXT_BYTES - 1] = 0x55;
  const maxPadded = padToBucket(maxPlaintext, ENVELOPE_OVERHEAD_BYTES);
  const maxUnpadded = unpadFromBucket(maxPadded, ENVELOPE_OVERHEAD_BYTES);
  assert(
    maxUnpadded.byteLength === MAX_PLAINTEXT_BYTES &&
      maxUnpadded[0] === 0xaa &&
      maxUnpadded[MAX_PLAINTEXT_BYTES - 1] === 0x55,
    'Exact 1 MiB plaintext pads and unpads cleanly',
  );
  wipeBuffers(maxPlaintext, maxPadded, maxUnpadded);

  // unpadFromBucket rejects length header larger than buffer
  const corruptHeaderGreaterThanBuf = new Uint8Array(PADDING_BUCKET_BYTES);
  new DataView(corruptHeaderGreaterThanBuf.buffer).setUint32(
    0,
    PADDING_BUCKET_BYTES - 3,
    false,
  );
  assertThrowsDecryptionErrorSync(
    () => unpadFromBucket(corruptHeaderGreaterThanBuf, 0),
    'Length header (253) larger than available buffer (252)',
  );

  const corruptHeaderMaxUint32 = new Uint8Array(PADDING_BUCKET_BYTES);
  new DataView(corruptHeaderMaxUint32.buffer).setUint32(0, 0xffffffff, false);
  assertThrowsDecryptionErrorSync(
    () => unpadFromBucket(corruptHeaderMaxUint32, 0),
    'Length header 0xFFFFFFFF larger than buffer',
  );

  // unpadFromBucket rejects oversize input (> 1 MiB ceiling) and header > 1 MiB
  const oversizePaddedBuffer = new Uint8Array(
    maxPaddedBytesForOverhead(0) + PADDING_BUCKET_BYTES,
  );
  new DataView(oversizePaddedBuffer.buffer).setUint32(
    0,
    MAX_PLAINTEXT_BYTES,
    false,
  );
  assertThrowsDecryptionErrorSync(
    () => unpadFromBucket(oversizePaddedBuffer, 0),
    'Oversize padded buffer exceeding 1 MiB ceiling',
  );

  const maxValidBucketBuffer = new Uint8Array(maxPaddedBytesForOverhead(0));
  new DataView(maxValidBucketBuffer.buffer).setUint32(
    0,
    MAX_PLAINTEXT_BYTES + 1,
    false,
  );
  assertThrowsDecryptionErrorSync(
    () => unpadFromBucket(maxValidBucketBuffer, 0),
    'Length header (1 MiB + 1) inside max bucket buffer',
  );

  // Requirement F: unpadFromBucket rejects non-zero byte at EVERY padding byte position
  const shortSample = new Uint8Array([1, 2, 3]);
  const cleanPaddedBuf = padToBucket(shortSample, 0);
  const firstPaddingByteIdx = PADDING_LENGTH_PREFIX_BYTES + shortSample.byteLength;
  assert(
    cleanPaddedBuf.byteLength - firstPaddingByteIdx === 249,
    'Expected 249 padding bytes for 3-byte payload',
  );
  for (let padPos = firstPaddingByteIdx; padPos < cleanPaddedBuf.byteLength; padPos++) {
    const mutatedPaddedBuf = cleanPaddedBuf.slice();
    mutatedPaddedBuf[padPos] = 0x01;
    assertThrowsDecryptionErrorSync(
      () => unpadFromBucket(mutatedPaddedBuf, 0),
      `Non-zero padding byte at index ${padPos} must throw DecryptionError`,
    );
  }

  // unpadFromBucket rejects non-minimal bucket padding (extra 256-byte zero block)
  const overPaddedBuf = new Uint8Array(PADDING_BUCKET_BYTES * 2);
  new DataView(overPaddedBuf.buffer).setUint32(0, 10, false);
  assertThrowsDecryptionErrorSync(
    () => unpadFromBucket(overPaddedBuf, 0),
    'Over-padded buffer with >= 256 trailing padding bytes',
  );

  // AES-256-GCM encrypt/decrypt round-trip and oversize envelope rejection
  const aesKey = await generateAesGcmKey(['encrypt', 'decrypt']);
  assert(
    aesKey.extractable === false,
    'Generated AES key is non-extractable',
  );
  const metaAad = makeAadForPurpose('item-meta', { revision: 1 });

  for (const len of [0, 1, 64, 223, 224, 500]) {
    const pt = secureRandom(len);
    const ct = await encrypt(aesKey, pt, metaAad);
    assert(
      ct.byteLength % PADDING_BUCKET_BYTES === 0,
      `Encrypted ciphertext for ${len}B plaintext is padded to 256B bucket`,
    );
    const rt = await decrypt(aesKey, ct, metaAad);
    assertBytesEqual(
      rt,
      pt,
      `AES-256-GCM encrypt/decrypt round-trip for ${len}B`,
    );
    wipeBuffers(pt, rt);
  }

  const oversizeEnvelope = new Uint8Array(
    MAX_ENCRYPTED_ENVELOPE_BYTES + PADDING_BUCKET_BYTES,
  );
  oversizeEnvelope[0] = ENVELOPE_VERSION_V1;
  await assertRejectsWithDecryptionError(
    () => decrypt(aesKey, oversizeEnvelope, metaAad),
    'Oversize encrypted envelope (> 1 MiB ceiling)',
  );

  // Requirement C: rewrapKey round-trip, old KEK rejection, wrong old AAD rejection
  const oldKek = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const newKek = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const prfWrappingKey = await generateAesGcmKey(['wrapKey', 'unwrapKey']);

  const kmAadV1 = makeAadForPurpose('vault-key-km', { keyVersion: 1 });
  const ksMasterAadV1 = makeAadForPurpose('vault-key-ks-master', { keyVersion: 1 });
  const ksPrfAadV1 = makeAadForPurpose('vault-key-ks-prf', {
    credentialId: 'passkey-cred-abc',
    keyVersion: 1,
  });

  const { key: km, wrappedKey: wrappedKmOld } = await createAndWrapVaultKey(
    oldKek,
    kmAadV1,
  );
  const { key: ks, wrappedKey: wrappedKsOld } = await createAndWrapVaultKey(
    oldKek,
    ksMasterAadV1,
  );

  const itemAad: ItemAadContext = {
    userId: 'user-1111-2222',
    itemId: 'item-3333-4444',
    keyVersion: 1,
    schemaVersion: 1,
    revision: 1,
  };
  const itemMetadata = secureRandom(120);
  const itemSecret = secureRandom(45);
  const encryptedItem = await encryptItem(
    { metadataKey: km, secretKey: ks },
    { metadata: itemMetadata, secret: itemSecret },
    itemAad,
  );

  // Re-wrap K_m and K_s under newKek (master password change) and K_s under prfWrappingKey (passkey registration)
  const wrappedKmNew = await rewrapKey(
    oldKek,
    wrappedKmOld,
    kmAadV1,
    newKek,
    kmAadV1,
  );
  const wrappedKsPrf = await rewrapKey(
    oldKek,
    wrappedKsOld,
    ksMasterAadV1,
    prfWrappingKey,
    ksPrfAadV1,
  );

  // Old KEK can no longer unwrap the new envelope
  await assertRejectsWithDecryptionError(
    () => unwrapKey(oldKek, wrappedKmNew, kmAadV1),
    'Old KEK must fail to unwrap re-wrapped K_m envelope',
  );
  await assertRejectsWithDecryptionError(
    () => unwrapKey(oldKek, wrappedKsPrf, ksPrfAadV1),
    'Old KEK must fail to unwrap PRF re-wrapped K_s envelope',
  );

  // Wrong old AAD fails in rewrapKey
  await assertRejectsWithDecryptionError(
    () => rewrapKey(oldKek, wrappedKmOld, ksMasterAadV1, newKek, kmAadV1),
    'rewrapKey with wrong oldAad purpose must fail',
  );
  await assertRejectsWithDecryptionError(
    () =>
      rewrapKey(
        oldKek,
        wrappedKmOld,
        makeAadForPurpose('vault-key-km', { userId: 'wrong-user' }),
        newKek,
        kmAadV1,
      ),
    'rewrapKey with wrong oldAad userId must fail',
  );

  // Unwrap K_m under newKek and K_s under prfWrappingKey and verify item decryption succeeds
  const unwrappedKmNew = await unwrapKey(newKek, wrappedKmNew, kmAadV1);
  const unwrappedKsPrf = await unwrapKey(
    prfWrappingKey,
    wrappedKsPrf,
    ksPrfAadV1,
  );
  const decryptedAfterRewrap = await decryptItem(
    { metadataKey: unwrappedKmNew, secretKey: unwrappedKsPrf },
    encryptedItem,
    itemAad,
  );
  assertBytesEqual(
    decryptedAfterRewrap.metadata,
    itemMetadata,
    'Re-wrapped K_m decrypts item metadata',
  );
  assertBytesEqual(
    decryptedAfterRewrap.secret,
    itemSecret,
    'PRF re-wrapped K_s decrypts item secret',
  );

  wipeBuffers(
    itemMetadata,
    itemSecret,
    decryptedAfterRewrap.metadata,
    decryptedAfterRewrap.secret,
  );
}

/**
 * 5. AAD Purpose Domain Separation (7x6 matrix, K_m vs K_s slot swap,
 *    ks-master vs ks-prf, 256-byte field ceiling, raw Uint8Array rejection,
 *    and item revision rollback) (Requirement B).
 */
async function testAadPurposeSeparationAndBounds(): Promise<void> {
  const dataKey = await generateAesGcmKey(['encrypt', 'decrypt']);
  const wrappingKey = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const payload = secureRandom(64);
  const rawKeyToWrap = secureRandom(AES_256_KEY_BYTES);

  // 5a. Exhaustive 7x6 cross-purpose check: ciphertext and wrapped key made
  //     for one purpose MUST fail under every other purpose.
  for (const sourcePurpose of AAD_PURPOSES) {
    const sourceAad = makeAadForPurpose(sourcePurpose, { revision: 1 });
    const ct = await encrypt(dataKey, payload, sourceAad);
    const wrapped = await wrapKey(wrappingKey, rawKeyToWrap, sourceAad);

    for (const targetPurpose of AAD_PURPOSES) {
      if (targetPurpose === sourcePurpose) {
        continue;
      }
      const targetAad = makeAadForPurpose(targetPurpose, { revision: 1 });
      await assertRejectsWithDecryptionError(
        () => decrypt(dataKey, ct, targetAad),
        `decrypt ciphertext made for "${sourcePurpose}" under "${targetPurpose}"`,
      );
      await assertRejectsWithDecryptionError(
        () => unwrapKey(wrappingKey, wrapped, targetAad),
        `unwrapKey made for "${sourcePurpose}" under "${targetPurpose}"`,
      );
    }
  }

  // 5b. Wrapped K_s placed in the K_m slot fails to unwrap, and vice versa;
  //     a ks-master blob fails under ks-prf, and ks-prf fails under a different credential_id.
  const kmAad = makeAadForPurpose('vault-key-km');
  const ksMasterAad = makeAadForPurpose('vault-key-ks-master');
  const ksPrfAad1 = makeAadForPurpose('vault-key-ks-prf', {
    credentialId: 'cred-id-1',
  });
  const ksPrfAad2 = makeAadForPurpose('vault-key-ks-prf', {
    credentialId: 'cred-id-2',
  });

  const { wrappedKey: wrappedKm } = await createAndWrapVaultKey(
    wrappingKey,
    kmAad,
  );
  const { wrappedKey: wrappedKsMaster } = await createAndWrapVaultKey(
    wrappingKey,
    ksMasterAad,
  );
  const { wrappedKey: wrappedKsPrf1 } = await createAndWrapVaultKey(
    wrappingKey,
    ksPrfAad1,
  );

  await assertRejectsWithDecryptionError(
    () => unwrapKey(wrappingKey, wrappedKsMaster, kmAad),
    'Wrapped K_s placed in K_m slot must fail to unwrap',
  );
  await assertRejectsWithDecryptionError(
    () => unwrapKey(wrappingKey, wrappedKm, ksMasterAad),
    'Wrapped K_m placed in K_s slot must fail to unwrap',
  );
  await assertRejectsWithDecryptionError(
    () => unwrapKey(wrappingKey, wrappedKsMaster, ksPrfAad1),
    'ks-master blob must fail to unwrap under ks-prf AAD',
  );
  await assertRejectsWithDecryptionError(
    () => unwrapKey(wrappingKey, wrappedKsPrf1, ksMasterAad),
    'ks-prf blob must fail to unwrap under ks-master AAD',
  );
  await assertRejectsWithDecryptionError(
    () => unwrapKey(wrappingKey, wrappedKsPrf1, ksPrfAad2),
    'ks-prf blob must fail to unwrap under a different passkey credential_id',
  );

  // 5c. Raw Uint8Array passed as AAD is a compile-time type error AND runtime error
  const rawAadBytes = encodeAad(makeAadForPurpose('item-meta'));
  const validCt = await encrypt(
    dataKey,
    payload,
    makeAadForPurpose('item-meta'),
  );
  assertThrowsCryptoArgumentErrorSync(
    // @ts-expect-error -- encodeAad rejects raw Uint8Array
    () => encodeAad(rawAadBytes),
    'encodeAad rejects raw Uint8Array',
  );
  await assertRejectsWithCryptoArgumentError(
    // @ts-expect-error -- encrypt rejects raw Uint8Array AAD
    () => encrypt(dataKey, payload, rawAadBytes),
    'encrypt rejects raw Uint8Array AAD',
  );
  await assertRejectsWithDecryptionError(
    // @ts-expect-error -- decrypt rejects raw Uint8Array AAD
    () => decrypt(dataKey, validCt, rawAadBytes),
    'decrypt rejects raw Uint8Array AAD',
  );
  await assertRejectsWithCryptoArgumentError(
    // @ts-expect-error -- wrapKey rejects raw Uint8Array AAD
    () => wrapKey(wrappingKey, rawKeyToWrap, rawAadBytes),
    'wrapKey rejects raw Uint8Array AAD',
  );
  await assertRejectsWithDecryptionError(
    // @ts-expect-error -- unwrapKey rejects raw Uint8Array AAD
    () => unwrapKey(wrappingKey, wrappedKm, rawAadBytes),
    'unwrapKey rejects raw Uint8Array AAD',
  );

  // 5d. Max length (256 bytes) enforced on userId, itemId, and credentialId BEFORE encoding,
  //     and uint32 bounds enforced on keyVersion, schemaVersion, and revision.
  const id256 = 'a'.repeat(MAX_AAD_ID_BYTES);
  const id257 = 'a'.repeat(MAX_AAD_ID_BYTES + 1);
  // 130 2-byte UTF-8 chars: string.length === 130 <= 256, but UTF-8 byteLength === 260 > 256
  const idMultiByteOver256 = '\u00e9'.repeat(130);

  assert(
    encodeAad(
      makeAadForPurpose('item-meta', { userId: id256, itemId: id256 }),
    ).byteLength > 0,
    '256-byte userId and itemId succeed',
  );
  assert(
    encodeAad(
      makeAadForPurpose('vault-key-ks-prf', {
        userId: id256,
        credentialId: id256,
      }),
    ).byteLength > 0,
    '256-byte credentialId succeeds',
  );

  for (const oversize of [
    id257,
    idMultiByteOver256,
    new Uint8Array(MAX_AAD_ID_BYTES + 1),
    '',
    new Uint8Array(0),
  ]) {
    assertThrowsCryptoArgumentErrorSync(
      () => encodeAad(makeAadForPurpose('item-meta', { userId: oversize })),
      'Invalid/oversize userId rejected',
    );
    assertThrowsCryptoArgumentErrorSync(
      () => encodeAad(makeAadForPurpose('item-meta', { itemId: oversize })),
      'Invalid/oversize itemId rejected',
    );
    assertThrowsCryptoArgumentErrorSync(
      () =>
        encodeAad(
          makeAadForPurpose('vault-key-ks-prf', { credentialId: oversize }),
        ),
      'Invalid/oversize credentialId rejected',
    );
  }

  for (const badUint32 of [0, -1, 0x1_0000_0000, 1.5, Number.NaN]) {
    assertThrowsCryptoArgumentErrorSync(
      () => encodeAad(makeAadForPurpose('item-meta', { keyVersion: badUint32 })),
      `Invalid keyVersion ${String(badUint32)} rejected`,
    );
    assertThrowsCryptoArgumentErrorSync(
      () =>
        encodeAad(makeAadForPurpose('item-meta', { schemaVersion: badUint32 })),
      `Invalid schemaVersion ${String(badUint32)} rejected`,
    );
    assertThrowsCryptoArgumentErrorSync(
      () => encodeAad(makeAadForPurpose('item-meta', { revision: badUint32 })),
      `Invalid item revision ${String(badUint32)} rejected`,
    );
  }
  for (const badVaultRev of [-1, 0x1_0000_0000, 1.5, Number.NaN]) {
    assertThrowsCryptoArgumentErrorSync(
      () =>
        encodeAad(
          makeAadForPurpose('vault-key-km', { revision: badVaultRev }),
        ),
      `Invalid vault-key revision ${String(badVaultRev)} rejected`,
    );
  }

  // 5e. Swapping wrappedItemKeyM and wrappedItemKeyS under identical vault key fails;
  //     item revision rollback fails.
  const itemAadRev1: ItemAadContext = {
    userId: 'user-domain-sep',
    itemId: 'item-domain-sep',
    keyVersion: 1,
    schemaVersion: 1,
    revision: 1,
  };
  const itemRev1 = await encryptItem(
    { metadataKey: wrappingKey, secretKey: wrappingKey },
    { metadata: payload, secret: payload },
    itemAadRev1,
  );

  await assertRejectsWithDecryptionError(
    () =>
      decryptItem(
        { metadataKey: wrappingKey, secretKey: wrappingKey },
        {
          ...itemRev1,
          wrappedItemKeyM: itemRev1.wrappedItemKeyS,
          wrappedItemKeyS: itemRev1.wrappedItemKeyM,
        },
        itemAadRev1,
      ),
    'Swapped wrappedItemKeyM and wrappedItemKeyS under identical vault key',
  );

  const itemAadRev2: ItemAadContext = {
    ...itemAadRev1,
    revision: 2,
  };
  await assertRejectsWithDecryptionError(
    () =>
      decryptItem(
        { metadataKey: wrappingKey, secretKey: wrappingKey },
        itemRev1,
        itemAadRev2,
      ),
    'Old item revision (1) blob decrypted with newer revision (2) AAD',
  );
  await assertRejectsWithDecryptionError(
    () => decryptItemMetadata(wrappingKey, itemRev1, itemAadRev2),
    'Old item revision (1) metaBlob decrypted with newer revision (2) AAD',
  );
  await assertRejectsWithDecryptionError(
    () => decryptItemSecret(wrappingKey, itemRev1, itemAadRev2),
    'Old item revision (1) secretBlob decrypted with newer revision (2) AAD',
  );

  wipeBuffers(payload, rawKeyToWrap);
}

/**
 * 6. Tampering, Wrong Key, Swapped AAD, and Partial-Failure Plaintext Wiping
 *    in `decryptItem` (Requirement D.1).
 */
async function testTamperingAndPartialFailureWiping(): Promise<void> {
  const key = await generateAesGcmKey(['encrypt', 'decrypt']);
  const aad = makeAadForPurpose('item-meta', {
    userId: 'user-tamper-test',
    itemId: 'item-tamper-test',
    keyVersion: 2,
    schemaVersion: 1,
    revision: 3,
  });
  const plaintext = secureRandom(88);
  const envelope = await encrypt(key, plaintext, aad);

  // 6a. Flipped bit in version byte (byte 0)
  for (let bit = 0; bit < 8; bit++) {
    const tamperedVersion = envelope.slice();
    tamperedVersion[0] = (tamperedVersion[0] ?? 0) ^ (1 << bit);
    await assertRejectsWithDecryptionError(
      () => decrypt(key, tamperedVersion, aad),
      `Flipped bit ${bit} in version byte`,
    );
  }

  // 6b. Flipped bit in nonce (bytes 1..12)
  for (let byteIdx = 1; byteIdx < ENVELOPE_HEADER_BYTES; byteIdx++) {
    const tamperedNonce = envelope.slice();
    tamperedNonce[byteIdx] = (tamperedNonce[byteIdx] ?? 0) ^ 0x01;
    await assertRejectsWithDecryptionError(
      () => decrypt(key, tamperedNonce, aad),
      `Flipped bit in nonce at byte ${byteIdx}`,
    );
  }

  // 6c. Flipped bit in ciphertext + GCM authentication tag (bytes 13..end)
  for (const byteIdx of [
    ENVELOPE_HEADER_BYTES,
    ENVELOPE_HEADER_BYTES + 10,
    envelope.byteLength - 17,
    envelope.byteLength - 1,
  ]) {
    const tamperedCiphertext = envelope.slice();
    tamperedCiphertext[byteIdx] = (tamperedCiphertext[byteIdx] ?? 0) ^ 0x80;
    await assertRejectsWithDecryptionError(
      () => decrypt(key, tamperedCiphertext, aad),
      `Flipped bit in ciphertext/tag at byte ${byteIdx}`,
    );
  }

  // 6d. Wrong key and swapped AAD fields fail
  const wrongKey = await generateAesGcmKey(['encrypt', 'decrypt']);
  await assertRejectsWithDecryptionError(
    () => decrypt(wrongKey, envelope, aad),
    'Wrong AES-256-GCM key',
  );
  await assertRejectsWithDecryptionError(
    () =>
      decrypt(
        key,
        envelope,
        makeAadForPurpose('item-meta', {
          userId: 'user-tamper-test',
          itemId: 'item-OTHER',
          keyVersion: 2,
          schemaVersion: 1,
          revision: 3,
        }),
      ),
    'Swapped itemId in AAD',
  );
  await assertRejectsWithDecryptionError(
    () =>
      decrypt(
        key,
        envelope,
        makeAadForPurpose('item-meta', {
          userId: 'user-tamper-testi',
          itemId: 'tem-tamper-test',
          keyVersion: 2,
          schemaVersion: 1,
          revision: 3,
        }),
      ),
    'Boundary-shifted userId/itemId in AAD',
  );

  // 6e. Requirement D.1: decryptItem uses Promise.allSettled and wipes any
  //     fulfilled plaintext buffer when the sibling blob is tampered with.
  const km = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const ks = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const itemAad: ItemAadContext = {
    userId: 'user-tamper-test',
    itemId: 'item-tamper-test',
    keyVersion: 2,
    schemaVersion: 1,
    revision: 3,
  };
  const metaPlain = new Uint8Array(37).fill(0x4d);
  const secretPlain = new Uint8Array(53).fill(0x53);
  const item = await encryptItem(
    { metadataKey: km, secretKey: ks },
    { metadata: metaPlain, secret: secretPlain },
    itemAad,
  );

  // Capture Uint8Array slices matching metaPlain (37B) or secretPlain (53B) returned by unpadFromBucket
  const originalSlice = Uint8Array.prototype.slice;
  const capturedSlices: Uint8Array[] = [];
  Uint8Array.prototype.slice = function (start?: number, end?: number): Uint8Array {
    const result = originalSlice.call(this, start, end);
    if (result.byteLength === 37 || result.byteLength === 53) {
      capturedSlices.push(result);
    }
    return result;
  };

  try {
    // Tamper ONLY with metaBlob; secretBlob is intact and will fulfill first/concurrently
    const tamperedMetaBlob = item.metaBlob.slice();
    tamperedMetaBlob[20] = (tamperedMetaBlob[20] ?? 0) ^ 0xff;
    capturedSlices.length = 0;

    await assertRejectsWithDecryptionError(
      () =>
        decryptItem(
          { metadataKey: km, secretKey: ks },
          { ...item, metaBlob: tamperedMetaBlob },
          itemAad,
        ),
      'Tampered metaBlob with intact secretBlob must reject',
    );
    assert(
      capturedSlices.length === 1 && capturedSlices[0]?.byteLength === 53,
      'Fulfilled secretBlob produced 53B unpadded slice before sibling failed',
    );
    assertBytesEqual(
      capturedSlices[0] ?? new Uint8Array([1]),
      new Uint8Array(53),
      'decryptItem wiped fulfilled secret plaintext buffer before throwing',
    );

    // Tamper ONLY with secretBlob; metaBlob is intact and will fulfill
    const tamperedSecretBlob = item.secretBlob.slice();
    tamperedSecretBlob[20] = (tamperedSecretBlob[20] ?? 0) ^ 0xff;
    capturedSlices.length = 0;

    await assertRejectsWithDecryptionError(
      () =>
        decryptItem(
          { metadataKey: km, secretKey: ks },
          { ...item, secretBlob: tamperedSecretBlob },
          itemAad,
        ),
      'Tampered secretBlob with intact metaBlob must reject',
    );
    assert(
      capturedSlices.length === 1 && capturedSlices[0]?.byteLength === 37,
      'Fulfilled metaBlob produced 37B unpadded slice before sibling failed',
    );
    assertBytesEqual(
      capturedSlices[0] ?? new Uint8Array([1]),
      new Uint8Array(37),
      'decryptItem wiped fulfilled metadata plaintext buffer before throwing',
    );
  } finally {
    Uint8Array.prototype.slice = originalSlice;
  }

  wipeBuffers(plaintext, metaPlain, secretPlain);
}

/**
 * 7. Mid-Operation Failure Wiping Test for `createAndWrapVaultKey` and `encryptItem`.
 */
async function testMidOperationFailureWiping(): Promise<void> {
  const originalGetRandomValues =
    globalThis.crypto.getRandomValues.bind(globalThis.crypto);
  const capturedKeyBuffers: Uint8Array[] = [];

  globalThis.crypto.getRandomValues = <T extends ArrayBufferView | null>(
    array: T,
  ): T => {
    const result = originalGetRandomValues(array);
    if (array instanceof Uint8Array && array.byteLength === AES_256_KEY_BYTES) {
      capturedKeyBuffers.push(
        new Uint8Array(array.buffer, array.byteOffset, array.byteLength),
      );
    }
    return result;
  };

  try {
    // 7a. Force createAndWrapVaultKey to fail mid-operation after generating
    //     rawKey (32B) by making subtle.wrapKey reject.
    const validWrappingKey = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
    const wrapAad = makeAadForPurpose('vault-key-km');
    const originalWrapKey = globalThis.crypto.subtle.wrapKey.bind(
      globalThis.crypto.subtle,
    );

    let wrapCallCount = 0;
    globalThis.crypto.subtle.wrapKey = async (
      ...args: Parameters<SubtleCrypto['wrapKey']>
    ): Promise<ArrayBuffer> => {
      wrapCallCount++;
      if (wrapCallCount === 1) {
        throw new Error('Simulated WebCrypto wrapKey failure');
      }
      return await originalWrapKey(...args);
    };

    try {
      capturedKeyBuffers.length = 0;
      let createFailed = false;
      try {
        await createAndWrapVaultKey(validWrappingKey, wrapAad);
      } catch {
        createFailed = true;
      }
      assert(
        createFailed,
        'createAndWrapVaultKey must fail when subtle.wrapKey rejects',
      );
      assert(
        capturedKeyBuffers.length === 1,
        'createAndWrapVaultKey allocated 1 raw 32-byte key buffer before failing',
      );
      assertBytesEqual(
        capturedKeyBuffers[0] ?? new Uint8Array([1]),
        new Uint8Array(AES_256_KEY_BYTES),
        'createAndWrapVaultKey wiped rawKey (all 32 bytes == 0) in finally after mid-op failure',
      );
    } finally {
      globalThis.crypto.subtle.wrapKey = originalWrapKey;
    }

    // 7b. Force encryptItem to fail mid-operation AFTER generating both
    //     rawItemKeyM (32B) and rawItemKeyS (32B) and wrapping rawItemKeyM,
    //     by failing on the second subtle.wrapKey call.
    const validKm = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
    const validKs = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
    const itemAad: ItemAadContext = {
      userId: 'user-wipe-test',
      itemId: 'item-wipe-test',
      keyVersion: 1,
      schemaVersion: 1,
      revision: 1,
    };

    wrapCallCount = 0;
    globalThis.crypto.subtle.wrapKey = async (
      ...args: Parameters<SubtleCrypto['wrapKey']>
    ): Promise<ArrayBuffer> => {
      wrapCallCount++;
      if (wrapCallCount === 2) {
        throw new Error('Simulated WebCrypto wrapKey failure on second key');
      }
      return await originalWrapKey(...args);
    };

    try {
      capturedKeyBuffers.length = 0;
      let encryptItemFailed = false;
      try {
        await encryptItem(
          { metadataKey: validKm, secretKey: validKs },
          { metadata: new Uint8Array([1, 2]), secret: new Uint8Array([3, 4]) },
          itemAad,
        );
      } catch {
        encryptItemFailed = true;
      }
      assert(
        encryptItemFailed,
        'encryptItem must fail mid-operation when wrapping rawItemKeyS fails',
      );
      assert(
        capturedKeyBuffers.length === 2,
        'encryptItem allocated 2 raw 32-byte item key buffers (rawItemKeyM and rawItemKeyS)',
      );
      assertBytesEqual(
        capturedKeyBuffers[0] ?? new Uint8Array([1]),
        new Uint8Array(AES_256_KEY_BYTES),
        'encryptItem wiped rawItemKeyM (all 32 bytes == 0) in finally after mid-op failure',
      );
      assertBytesEqual(
        capturedKeyBuffers[1] ?? new Uint8Array([1]),
        new Uint8Array(AES_256_KEY_BYTES),
        'encryptItem wiped rawItemKeyS (all 32 bytes == 0) in finally after mid-op failure',
      );
    } finally {
      globalThis.crypto.subtle.wrapKey = originalWrapKey;
    }
  } finally {
    globalThis.crypto.getRandomValues = originalGetRandomValues;
  }
}

/**
 * 8. Nonce Uniqueness over 100,000 `encrypt` calls AND `wrapKey` calls (Requirement F).
 */
async function testNonceUniqueness(): Promise<void> {
  const totalEncryptions = 100_000;
  const dataKey = await generateAesGcmKey(['encrypt', 'decrypt']);
  const itemAad = makeAadForPurpose('item-meta', {
    userId: 'user-nonce-test',
    itemId: 'item-nonce-test',
    revision: 1,
  });
  const payload = new Uint8Array([0x42]);
  const seenEncryptNonces = new Set<string>();

  for (let i = 0; i < totalEncryptions; i++) {
    const env = await encrypt(dataKey, payload, itemAad);
    const nonce = env.subarray(1, 1 + AES_GCM_NONCE_BYTES);
    const nonceHex = bytesToHex(nonce);
    assert(
      !seenEncryptNonces.has(nonceHex),
      `Duplicate encrypt() nonce detected at index ${i}`,
    );
    seenEncryptNonces.add(nonceHex);
  }
  assert(
    seenEncryptNonces.size === totalEncryptions,
    `Expected ${totalEncryptions} unique encrypt() nonces`,
  );

  // Also verify nonce uniqueness for wrapKey
  const totalWraps = 5_000;
  const wrappingKey = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const wrapAad = makeAadForPurpose('vault-key-km');
  const rawKeyToWrap = secureRandom(AES_256_KEY_BYTES);
  const seenWrapNonces = new Set<string>();

  for (let i = 0; i < totalWraps; i++) {
    const env = await wrapKey(wrappingKey, rawKeyToWrap, wrapAad);
    const nonce = env.subarray(1, 1 + AES_GCM_NONCE_BYTES);
    const nonceHex = bytesToHex(nonce);
    assert(
      !seenWrapNonces.has(nonceHex),
      `Duplicate wrapKey() nonce detected at index ${i}`,
    );
    seenWrapNonces.add(nonceHex);
  }
  assert(
    seenWrapNonces.size === totalWraps,
    `Expected ${totalWraps} unique wrapKey() nonces`,
  );
  wipeBuffer(rawKeyToWrap);
}

/**
 * 9. Secret Key CRC-7 Checksum: 100% of single-character substitutions
 *    (27 x 31 = 837) AND 100% of two-character transpositions at any distance
 *    (Requirement F).
 */
function testSecretKeyChecksumSubstitutionsAndTranspositions(): void {
  const validKey = generateSecretKey();
  const payloadOnly = validKey.replace(/-/g, '').slice(SECRET_KEY_PREFIX.length);
  assert(
    payloadOnly.length === SECRET_KEY_BASE32_CHARS,
    `Expected ${SECRET_KEY_BASE32_CHARS} Base32 characters, got ${payloadOnly.length}`,
  );

  const alternativesPerChar = SECRET_KEY_BASE32_ALPHABET.length - 1;
  const expectedMutationCount =
    SECRET_KEY_BASE32_CHARS * alternativesPerChar; // 27 * 31 = 837

  let rejectedMutations = 0;

  for (let pos = 0; pos < payloadOnly.length; pos++) {
    const originalChar = payloadOnly[pos];
    if (originalChar === undefined) {
      continue;
    }

    for (let c = 0; c < SECRET_KEY_BASE32_ALPHABET.length; c++) {
      const replacement = SECRET_KEY_BASE32_ALPHABET[c];
      if (replacement === undefined || replacement === originalChar) {
        continue;
      }

      const mutatedPayload =
        payloadOnly.slice(0, pos) + replacement + payloadOnly.slice(pos + 1);
      const mutatedKey = `${SECRET_KEY_PREFIX}-${mutatedPayload}`;

      let caught: unknown;
      try {
        parseSecretKey(mutatedKey);
      } catch (err: unknown) {
        caught = err;
      }

      assert(
        caught instanceof InvalidSecretKeyError &&
          caught.message === INVALID_SECRET_KEY_MESSAGE,
        `Single-character error at Base32 position ${pos} must throw InvalidSecretKeyError`,
      );
      rejectedMutations++;
    }
  }

  assert(
    rejectedMutations === expectedMutationCount && rejectedMutations === 837,
    `Expected 27 x 31 = 837 single-character mutations, got ${rejectedMutations}`,
  );

  // Two-character transpositions across all pairs (i, j) with 0 <= i < j < 27 where chars differ
  let testedTranspositions = 0;
  for (let i = 0; i < payloadOnly.length; i++) {
    for (let j = i + 1; j < payloadOnly.length; j++) {
      const charI = payloadOnly[i];
      const charJ = payloadOnly[j];
      if (charI === undefined || charJ === undefined || charI === charJ) {
        continue;
      }
      const chars = payloadOnly.split('');
      chars[i] = charJ;
      chars[j] = charI;
      const transposedKey = `${SECRET_KEY_PREFIX}-${chars.join('')}`;

      let caught: unknown;
      try {
        parseSecretKey(transposedKey);
      } catch (err: unknown) {
        caught = err;
      }
      assert(
        caught instanceof InvalidSecretKeyError &&
          caught.message === INVALID_SECRET_KEY_MESSAGE,
        `Transposition between positions ${i} and ${j} must throw InvalidSecretKeyError`,
      );
      testedTranspositions++;
    }
  }
  assert(
    testedTranspositions > 200,
    `Expected > 200 distinct two-character transpositions tested, got ${testedTranspositions}`,
  );

  // Prefix transposition ("3A-...") must also reject
  let prefixTranspositionRejected = false;
  try {
    parseSecretKey(`3A-${payloadOnly}`);
  } catch (err: unknown) {
    prefixTranspositionRejected = err instanceof InvalidSecretKeyError;
  }
  assert(
    prefixTranspositionRejected,
    'Transposed prefix "3A-..." must throw InvalidSecretKeyError',
  );
}

/**
 * 10. Assert no key material appears in any thrown error message across hex,
 *     decimal, Base64, Base32, UTF-8, or normalized Secret Key forms
 *     (Requirement F).
 */
async function testNoKeyMaterialInErrors(): Promise<void> {
  const rawSecretKey = secureRandom(SECRET_KEY_BYTES);
  const formattedSecretKey = formatSecretKey(rawSecretKey);
  const rawAesKey = secureRandom(AES_256_KEY_BYTES);
  const rawIkm = secureRandom(32);
  const sensitivePlaintextBytes = new TextEncoder().encode(
    'SuperSecretVaultPlaintext-987654321!',
  );

  const secretKeySlice10 = rawSecretKey.subarray(0, 10);
  const aesKeySlice15 = rawAesKey.subarray(0, 15);

  const lastChar = formattedSecretKey[formattedSecretKey.length - 1];
  const mutatedSecretKey =
    formattedSecretKey.slice(0, -1) + (lastChar === 'A' ? 'B' : 'A');
  const normalizedValidKey = formattedSecretKey.replace(/-/g, '');
  const normalizedMutatedKey = mutatedSecretKey.replace(/-/g, '');

  const sensitiveSubstrings: string[] = [
    formattedSecretKey,
    formattedSecretKey.toLowerCase(),
    normalizedValidKey,
    normalizedValidKey.toLowerCase(),
    mutatedSecretKey,
    mutatedSecretKey.toLowerCase(),
    normalizedMutatedKey,
    normalizedMutatedKey.toLowerCase(),
    'SuperSecretVaultPlaintext',
  ];

  for (const buf of [
    rawSecretKey,
    secretKeySlice10,
    rawAesKey,
    aesKeySlice15,
    rawIkm,
    sensitivePlaintextBytes,
  ]) {
    sensitiveSubstrings.push(
      bytesToHex(buf),
      Array.from(buf).join(','),
      bytesToBase64(buf),
      bytesToBase32(buf),
    );
  }

  const dataKey = await importAesGcmKey(rawAesKey, ['encrypt', 'decrypt']);
  const wrongDataKey = await generateAesGcmKey(['encrypt', 'decrypt']);
  const wrongWrappingKey = await generateAesGcmKey(['wrapKey', 'unwrapKey']);
  const aad = makeAadForPurpose('item-meta', {
    userId: 'user-error-scrub',
    itemId: 'item-error-scrub',
    keyVersion: 1,
    schemaVersion: 1,
    revision: 1,
  });
  const itemAad: ItemAadContext = {
    userId: 'user-error-scrub',
    itemId: 'item-error-scrub',
    keyVersion: 1,
    schemaVersion: 1,
    revision: 1,
  };
  const validCiphertext = await encrypt(dataKey, sensitivePlaintextBytes, aad);

  const errorTriggers: ReadonlyArray<() => Promise<unknown> | unknown> = [
    () => parseSecretKey(mutatedSecretKey),
    () => parseSecretKey(formattedSecretKey + 'X'),
    () => formatSecretKey(secretKeySlice10),
    () => hkdf(rawIkm, new Uint8Array(0), new Uint8Array(0), 0),
    () => hkdf(new Uint8Array(0), rawIkm, new Uint8Array(0), 32),
    () => derivePasswordInput('SuperSecretVaultPlaintext-987654321!', secretKeySlice10),
    () => importAesGcmKey(aesKeySlice15),
    () => decrypt(wrongDataKey, validCiphertext, aad),
    () => {
      const bad = validCiphertext.slice();
      bad[25] = (bad[25] ?? 0) ^ 0xff;
      return decrypt(dataKey, bad, aad);
    },
    () =>
      unwrapKey(
        wrongWrappingKey,
        validCiphertext.subarray(0, WRAPPED_KEY_ENVELOPE_BYTES),
        makeAadForPurpose('vault-key-km'),
      ),
    () =>
      decryptItem(
        { metadataKey: wrongWrappingKey, secretKey: wrongWrappingKey },
        {
          metaBlob: validCiphertext,
          secretBlob: validCiphertext,
          wrappedItemKeyM: validCiphertext.subarray(
            0,
            WRAPPED_KEY_ENVELOPE_BYTES,
          ),
          wrappedItemKeyS: validCiphertext.subarray(
            0,
            WRAPPED_KEY_ENVELOPE_BYTES,
          ),
        },
        itemAad,
      ),
  ];

  let caughtCount = 0;
  for (const trigger of errorTriggers) {
    try {
      await trigger();
    } catch (err: unknown) {
      caughtCount++;
      assert(
        err instanceof DecryptionError ||
          err instanceof InvalidSecretKeyError ||
          err instanceof CryptoArgumentError,
        'Error must be one of the uniform crypto error classes',
      );
      const serialized = [
        err instanceof Error ? err.message : '',
        err instanceof Error ? (err.stack ?? '') : '',
        String(err),
        JSON.stringify(err),
      ].join('\n');

      for (const secretFragment of sensitiveSubstrings) {
        assert(
          secretFragment.length > 0 &&
            !serialized.toLowerCase().includes(secretFragment.toLowerCase()),
          'Thrown error must never contain any key material, Secret Key, or plaintext in hex/decimal/base64/base32/normalized form',
        );
      }
    }
  }

  assert(
    caughtCount === errorTriggers.length,
    `All ${errorTriggers.length} error triggers must throw`,
  );

  wipeBuffers(rawSecretKey, rawAesKey, rawIkm, sensitivePlaintextBytes);
}

async function runAllTests(): Promise<void> {
  const suites: ReadonlyArray<{
    readonly name: string;
    readonly fn: () => Promise<void> | void;
  }> = [
    {
      name: 'RFC 5869 HKDF vectors, derivePasswordInput (NFKC + 16B salt), and deriveKek',
      fn: testRfc5869HkdfAndKeyDerivations,
    },
    {
      name: 'Official GCM Spec (McGrew & Viega Appendix B TC 13-16) vectors & node:crypto differential test',
      fn: testAes256GcmKnownAnswerAndNodeCrypto,
    },
    {
      name: 'Key usage group enforcement, non-extractability, and public API hygiene',
      fn: testKeyUsagesAndNonExtractability,
    },
    {
      name: 'Round-trip, normalization, rewrapKey, and padding bounds (every padding byte & 1 MiB ceiling)',
      fn: testRoundTripsRewrapAndPadding,
    },
    {
      name: 'AAD purpose separation (7x6 matrix, K_m/K_s swap, ks-prf credentialId, 256B limit, no raw bytes)',
      fn: testAadPurposeSeparationAndBounds,
    },
    {
      name: 'Tampering, wrong key, swapped AAD, and Promise.allSettled partial-failure wiping in decryptItem',
      fn: testTamperingAndPartialFailureWiping,
    },
    {
      name: 'Mid-operation failure wipes raw key buffers in createAndWrapVaultKey & encryptItem',
      fn: testMidOperationFailureWiping,
    },
    {
      name: 'Nonce uniqueness over 100,000 encrypt() calls and 5,000 wrapKey() calls',
      fn: testNonceUniqueness,
    },
    {
      name: 'Secret Key CRC-7 catches 100% of single-char errors (837) and two-char transpositions',
      fn: testSecretKeyChecksumSubstitutionsAndTranspositions,
    },
    {
      name: 'No key material appears in thrown errors (hex, decimal, base64, base32, normalized)',
      fn: testNoKeyMaterialInErrors,
    },
  ];

  console.log(`Running ${suites.length} Strongroom crypto test suites...\n`);
  for (const suite of suites) {
    const start = performance.now();
    await suite.fn();
    const elapsedMs = (performance.now() - start).toFixed(1);
    console.log(`PASS: ${suite.name} (${elapsedMs} ms)`);
  }
  console.log(`\nAll ${suites.length}/${suites.length} crypto test suites passed.`);
}

await runAllTests();
