import { type ItemAadContext, encodeAad } from './aad.ts';
import {
  AES_256_KEY_BYTES,
  decrypt,
  encrypt,
  importAesGcmKey,
  isAes256GcmWrappingKey,
} from './aesGcm.ts';
import { CryptoArgumentError, DecryptionError } from './errors.ts';
import { unwrapKey, wrapKey } from './keyWrap.ts';
import { wipeBuffer, wipeBuffers } from './memory.ts';
import { MAX_PLAINTEXT_BYTES } from './padding.ts';
import { secureRandom } from './random.ts';

/**
 * Vault key pair (`K_m` for metadata, `K_s` for secrets) per PRD Section 5.2.
 */
export interface VaultKeyPair {
  readonly metadataKey: CryptoKey;
  readonly secretKey: CryptoKey;
}

/**
 * Plaintext item payload before encryption (metadata and secret separated per
 * PRD Section 5.2).
 */
export interface PlaintextVaultItem {
  readonly metadata: Uint8Array;
  readonly secret: Uint8Array;
}

/**
 * Encrypted item blobs and wrapped per-item keys matching the `items` table
 * schema in PRD Section 5.2, 5.3, and 12.
 */
export interface EncryptedVaultItem {
  readonly metaBlob: Uint8Array;
  readonly secretBlob: Uint8Array;
  readonly wrappedItemKeyM: Uint8Array;
  readonly wrappedItemKeyS: Uint8Array;
  readonly paddedSize: number;
}

/**
 * Encrypts a vault item with fresh random 256-bit per-item keys and distinct
 * domain-separated AAD purpose labels:
 * - `wrappedItemKeyM`: fresh 256-bit item metadata key wrapped under `K_m`
 *   with `purpose: 'item-key-m'` and `aad.revision`.
 * - `wrappedItemKeyS`: fresh 256-bit item secret key wrapped under `K_s`
 *   with `purpose: 'item-key-s'` and `aad.revision`.
 * - `metaBlob`: `item.metadata` encrypted under `itemKeyM` with
 *   `purpose: 'item-meta'` and `aad.revision`, padded to a 256-byte bucket.
 * - `secretBlob`: `item.secret` encrypted under `itemKeyS` with
 *   `purpose: 'item-secret'` and `aad.revision`, padded to a 256-byte bucket.
 *
 * Raw key byte lifecycle:
 * 1. `rawItemKeyM` (32B) and `rawItemKeyS` (32B) are allocated inside `try`.
 * 2. Both are imported as non-extractable `CryptoKey`s via `importAesGcmKey`
 *    (which zeroes its temporary `ArrayBuffer` copies in `finally`).
 * 3. Both are wrapped via `wrapKey` (which zeroes its temporary `ArrayBuffer`
 *    copies in `finally`).
 * 4. `encryptItem`'s `finally` block unconditionally zeroes `rawItemKeyM`,
 *    `rawItemKeyS`, and all encoded AAD buffers on every path, including
 *    mid-operation errors.
 */
export async function encryptItem(
  vaultKeys: VaultKeyPair,
  item: PlaintextVaultItem,
  aad: ItemAadContext,
): Promise<EncryptedVaultItem> {
  if (
    typeof vaultKeys !== 'object' ||
    vaultKeys === null ||
    !isAes256GcmWrappingKey(vaultKeys.metadataKey, 'wrapKey') ||
    !isAes256GcmWrappingKey(vaultKeys.secretKey, 'wrapKey') ||
    typeof item !== 'object' ||
    item === null ||
    !(item.metadata instanceof Uint8Array) ||
    !(item.secret instanceof Uint8Array) ||
    item.metadata.byteLength > MAX_PLAINTEXT_BYTES ||
    item.secret.byteLength > MAX_PLAINTEXT_BYTES ||
    typeof aad !== 'object' ||
    aad === null
  ) {
    throw new CryptoArgumentError();
  }

  let rawItemKeyM: Uint8Array | undefined;
  let rawItemKeyS: Uint8Array | undefined;

  try {
    const aadKeyM = { ...aad, purpose: 'item-key-m' as const };
    const aadKeyS = { ...aad, purpose: 'item-key-s' as const };
    const aadMeta = { ...aad, purpose: 'item-meta' as const };
    const aadSecret = { ...aad, purpose: 'item-secret' as const };

    // Validate AAD fields upfront before allocating keys
    wipeBuffers(
      encodeAad(aadKeyM),
      encodeAad(aadKeyS),
      encodeAad(aadMeta),
      encodeAad(aadSecret),
    );

    rawItemKeyM = secureRandom(AES_256_KEY_BYTES);
    rawItemKeyS = secureRandom(AES_256_KEY_BYTES);

    const itemKeyM = await importAesGcmKey(rawItemKeyM, ['encrypt']);
    const itemKeyS = await importAesGcmKey(rawItemKeyS, ['encrypt']);

    const wrappedItemKeyM = await wrapKey(
      vaultKeys.metadataKey,
      rawItemKeyM,
      aadKeyM,
    );
    const wrappedItemKeyS = await wrapKey(
      vaultKeys.secretKey,
      rawItemKeyS,
      aadKeyS,
    );
    const metaBlob = await encrypt(itemKeyM, item.metadata, aadMeta);
    const secretBlob = await encrypt(itemKeyS, item.secret, aadSecret);

    return {
      metaBlob,
      secretBlob,
      wrappedItemKeyM,
      wrappedItemKeyS,
      paddedSize: metaBlob.byteLength + secretBlob.byteLength,
    };
  } finally {
    wipeBuffers(rawItemKeyM, rawItemKeyS);
  }
}

/**
 * Decrypts only the item's metadata using `K_m` (for browsing/searching the
 * vault list while `K_s` is not held in memory, per PRD Section 5.2).
 * Verifies `purpose: 'item-key-m'` on the wrapped key and `purpose: 'item-meta'`
 * on the metadata ciphertext, both bound to `aad.revision`.
 */
export async function decryptItemMetadata(
  metadataKey: CryptoKey,
  encryptedItem: Pick<EncryptedVaultItem, 'metaBlob' | 'wrappedItemKeyM'>,
  aad: ItemAadContext,
): Promise<Uint8Array> {
  try {
    if (
      !isAes256GcmWrappingKey(metadataKey, 'unwrapKey') ||
      typeof encryptedItem !== 'object' ||
      encryptedItem === null ||
      typeof aad !== 'object' ||
      aad === null
    ) {
      throw new DecryptionError();
    }
    const aadKeyM = { ...aad, purpose: 'item-key-m' as const };
    const aadMeta = { ...aad, purpose: 'item-meta' as const };

    const itemKeyM = await unwrapKey(
      metadataKey,
      encryptedItem.wrappedItemKeyM,
      aadKeyM,
      ['decrypt'],
    );
    return await decrypt(itemKeyM, encryptedItem.metaBlob, aadMeta);
  } catch {
    throw new DecryptionError();
  }
}

/**
 * Decrypts only the item's secret using `K_s` (for the biometric/PRF reveal
 * flow, per PRD Section 5.2 and 6).
 * Verifies `purpose: 'item-key-s'` on the wrapped key and `purpose: 'item-secret'`
 * on the secret ciphertext, both bound to `aad.revision`.
 */
export async function decryptItemSecret(
  secretKey: CryptoKey,
  encryptedItem: Pick<EncryptedVaultItem, 'secretBlob' | 'wrappedItemKeyS'>,
  aad: ItemAadContext,
): Promise<Uint8Array> {
  try {
    if (
      !isAes256GcmWrappingKey(secretKey, 'unwrapKey') ||
      typeof encryptedItem !== 'object' ||
      encryptedItem === null ||
      typeof aad !== 'object' ||
      aad === null
    ) {
      throw new DecryptionError();
    }
    const aadKeyS = { ...aad, purpose: 'item-key-s' as const };
    const aadSecret = { ...aad, purpose: 'item-secret' as const };

    const itemKeyS = await unwrapKey(
      secretKey,
      encryptedItem.wrappedItemKeyS,
      aadKeyS,
      ['decrypt'],
    );
    return await decrypt(itemKeyS, encryptedItem.secretBlob, aadSecret);
  } catch {
    throw new DecryptionError();
  }
}

/**
 * Decrypts both metadata and secret of an encrypted vault item using `K_m`
 * and `K_s`, verifying domain-separated AADs (`item-key-m`, `item-key-s`,
 * `item-meta`, `item-secret`) and `aad.revision` on all wrapped keys and
 * ciphertexts.
 *
 * Uses `Promise.allSettled` and wipes any fulfilled plaintext buffer if the
 * sibling decryption fails before throwing `DecryptionError`.
 */
export async function decryptItem(
  vaultKeys: VaultKeyPair,
  encryptedItem: Pick<
    EncryptedVaultItem,
    'metaBlob' | 'secretBlob' | 'wrappedItemKeyM' | 'wrappedItemKeyS'
  >,
  aad: ItemAadContext,
): Promise<PlaintextVaultItem> {
  if (
    typeof vaultKeys !== 'object' ||
    vaultKeys === null ||
    typeof encryptedItem !== 'object' ||
    encryptedItem === null
  ) {
    throw new DecryptionError();
  }

  const [metaResult, secretResult] = await Promise.allSettled([
    decryptItemMetadata(vaultKeys.metadataKey, encryptedItem, aad),
    decryptItemSecret(vaultKeys.secretKey, encryptedItem, aad),
  ]);

  if (
    metaResult.status !== 'fulfilled' ||
    secretResult.status !== 'fulfilled'
  ) {
    if (metaResult.status === 'fulfilled') {
      wipeBuffer(metaResult.value);
    }
    if (secretResult.status === 'fulfilled') {
      wipeBuffer(secretResult.value);
    }
    throw new DecryptionError();
  }

  return { metadata: metaResult.value, secret: secretResult.value };
}
