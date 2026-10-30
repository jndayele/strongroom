import { CryptoArgumentError } from './errors.ts';

/**
 * Allowed AAD domain-separation purpose labels.
 */
export const AAD_PURPOSES = [
  'item-meta',
  'item-secret',
  'item-key-m',
  'item-key-s',
  'vault-key-km',
  'vault-key-ks-master',
  'vault-key-ks-prf',
] as const;

export type AadPurpose = (typeof AAD_PURPOSES)[number];
export type ItemAadPurpose =
  | 'item-meta'
  | 'item-secret'
  | 'item-key-m'
  | 'item-key-s';
export type VaultKeyMasterAadPurpose = 'vault-key-km' | 'vault-key-ks-master';
export type VaultKeyAadPurpose = VaultKeyMasterAadPurpose | 'vault-key-ks-prf';

/**
 * Maximum allowed byte length (256 bytes) for `userId`, `itemId`, and
 * `credentialId` in AAD structures, enforced before encoding.
 */
export const MAX_AAD_ID_BYTES = 256 as const;

export interface BaseAadParams {
  readonly userId: string | Uint8Array;
  readonly itemId: string | Uint8Array;
  readonly keyVersion: number;
  readonly schemaVersion: number;
}

export interface ItemPurposeAadParams extends BaseAadParams {
  readonly purpose: ItemAadPurpose;
  readonly revision: number;
}

export interface VaultKeyMasterAadParams {
  readonly purpose: VaultKeyMasterAadPurpose;
  readonly userId: string | Uint8Array;
  readonly itemId?: string | Uint8Array;
  readonly keyVersion: number;
  readonly schemaVersion: number;
  readonly revision?: number;
}

export interface VaultKeyPrfAadParams {
  readonly purpose: 'vault-key-ks-prf';
  readonly userId: string | Uint8Array;
  readonly credentialId: string | Uint8Array;
  readonly keyVersion: number;
  readonly schemaVersion: number;
  readonly revision?: number;
}

export type VaultKeyWrapAadParams =
  | VaultKeyMasterAadParams
  | VaultKeyPrfAadParams;

/**
 * Authenticated Associated Data (AAD) fields binding every ciphertext and
 * wrapped key to its domain purpose, user, item/key/credential identifier,
 * key version, schema version, and revision.
 */
export type AadParams = ItemPurposeAadParams | VaultKeyWrapAadParams;

/**
 * Item-level AAD context passed to `encryptItem` / `decryptItem` /
 * `decryptItemMetadata` / `decryptItemSecret`. Each sub-operation stamps its
 * own domain-separation `purpose` (`item-key-m`, `item-key-s`, `item-meta`,
 * `item-secret`).
 */
export interface ItemAadContext extends BaseAadParams {
  readonly revision: number;
}

const MAX_UINT32 = 0xffffffff;

function toBoundedNonEmptyBytes(value: string | Uint8Array): Uint8Array {
  if (typeof value === 'string') {
    if (value.length === 0 || value.length > MAX_AAD_ID_BYTES) {
      throw new CryptoArgumentError();
    }
    const encoded = new TextEncoder().encode(value);
    if (encoded.byteLength === 0 || encoded.byteLength > MAX_AAD_ID_BYTES) {
      throw new CryptoArgumentError();
    }
    return encoded;
  }
  if (value instanceof Uint8Array) {
    if (value.byteLength === 0 || value.byteLength > MAX_AAD_ID_BYTES) {
      throw new CryptoArgumentError();
    }
    return value;
  }
  throw new CryptoArgumentError();
}

function assertPositiveUint32(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_UINT32) {
    throw new CryptoArgumentError();
  }
}

function assertNonNegativeUint32(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_UINT32) {
    throw new CryptoArgumentError();
  }
}

/**
 * Canonically serializes AAD with big-endian `uint32` length prefixes on all
 * variable-length fields (`purpose`, `user_id`, `item_id`/`credential_id`)
 * followed by fixed-width `uint32` big-endian integers (`key_version`,
 * `schema_version`, `revision`):
 *
 * ```text
 * [u32_be(len(purpose)) || purpose_utf8 ||
 *  u32_be(len(user_id)) || user_id      ||
 *  u32_be(len(target_id)) || target_id  ||
 *  u32_be(key_version)  ||
 *  u32_be(schema_version) ||
 *  u32_be(revision)]
 * ```
 */
export function encodeAad(params: AadParams): Uint8Array {
  if (
    typeof params !== 'object' ||
    params === null ||
    ArrayBuffer.isView(params as unknown)
  ) {
    throw new CryptoArgumentError();
  }

  if (typeof params.purpose !== 'string') {
    throw new CryptoArgumentError();
  }

  const purposeBytes = new TextEncoder().encode(params.purpose);
  const userIdBytes = toBoundedNonEmptyBytes(params.userId);
  const rawRecord = params as {
    readonly itemId?: unknown;
    readonly credentialId?: unknown;
  };

  let targetIdBytes: Uint8Array;
  let revisionValue: number;

  switch (params.purpose) {
    case 'vault-key-ks-prf': {
      if (rawRecord.itemId !== undefined) {
        throw new CryptoArgumentError();
      }
      targetIdBytes = toBoundedNonEmptyBytes(params.credentialId);
      revisionValue = params.revision ?? 0;
      assertNonNegativeUint32(revisionValue);
      break;
    }
    case 'vault-key-km':
    case 'vault-key-ks-master': {
      if (rawRecord.credentialId !== undefined) {
        throw new CryptoArgumentError();
      }
      targetIdBytes =
        params.itemId !== undefined
          ? toBoundedNonEmptyBytes(params.itemId)
          : purposeBytes;
      revisionValue = params.revision ?? 0;
      assertNonNegativeUint32(revisionValue);
      break;
    }
    case 'item-meta':
    case 'item-secret':
    case 'item-key-m':
    case 'item-key-s': {
      if (rawRecord.credentialId !== undefined) {
        throw new CryptoArgumentError();
      }
      targetIdBytes = toBoundedNonEmptyBytes(params.itemId);
      revisionValue = params.revision;
      assertPositiveUint32(revisionValue);
      break;
    }
    default: {
      throw new CryptoArgumentError();
    }
  }

  assertPositiveUint32(params.keyVersion);
  assertPositiveUint32(params.schemaVersion);

  const totalLength =
    4 +
    purposeBytes.byteLength +
    4 +
    userIdBytes.byteLength +
    4 +
    targetIdBytes.byteLength +
    4 +
    4 +
    4;

  const out = new Uint8Array(totalLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);

  let offset = 0;
  view.setUint32(offset, purposeBytes.byteLength, false);
  offset += 4;
  out.set(purposeBytes, offset);
  offset += purposeBytes.byteLength;

  view.setUint32(offset, userIdBytes.byteLength, false);
  offset += 4;
  out.set(userIdBytes, offset);
  offset += userIdBytes.byteLength;

  view.setUint32(offset, targetIdBytes.byteLength, false);
  offset += 4;
  out.set(targetIdBytes, offset);
  offset += targetIdBytes.byteLength;

  view.setUint32(offset, params.keyVersion, false);
  offset += 4;

  view.setUint32(offset, params.schemaVersion, false);
  offset += 4;

  view.setUint32(offset, revisionValue, false);

  return out;
}
