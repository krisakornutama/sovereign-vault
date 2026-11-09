import {
  concatBytes,
  equalsConstantTime,
  randomBytes,
  sha256,
  toBufferSource,
  utf8ToBytes,
} from './bytes.js';
import { VaultError, VaultIntegrityError } from './errors.js';

export const ENVELOPE_MAGIC = new Uint8Array([0x53, 0x56, 0x4c, 0x54]); // "SVLT"
export const ENVELOPE_VERSION = 1;
export const ENVELOPE_ALG_AES_256_GCM = 1;
export const MASTER_KEY_LENGTH = 32;
export const KEY_ID_LENGTH = 8;

const SALT_LENGTH = 16;
const NONCE_LENGTH = 12;
const HASH_LENGTH = 32;
const TAG_LENGTH = 16;
const RESERVED_LENGTH = 2;
const LENGTH_FIELD = 4;
const HEADER_LENGTH =
  ENVELOPE_MAGIC.length +
  1 + // version
  1 + // alg
  RESERVED_LENGTH +
  KEY_ID_LENGTH +
  SALT_LENGTH +
  NONCE_LENGTH +
  HASH_LENGTH +
  LENGTH_FIELD;

const KEY_INFO = utf8ToBytes('sovereign-vault/object-key/v1');

interface HeaderFields {
  readonly keyId: Uint8Array;
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly plaintextHash: Uint8Array;
  readonly ciphertextLength: number;
}

function buildHeader(fields: HeaderFields): Uint8Array {
  const header = new Uint8Array(HEADER_LENGTH);
  const view = new DataView(header.buffer);
  header.set(ENVELOPE_MAGIC, 0);
  header[4] = ENVELOPE_VERSION;
  header[5] = ENVELOPE_ALG_AES_256_GCM;
  view.setUint16(6, 0);
  header.set(fields.keyId, 8);
  header.set(fields.salt, 16);
  header.set(fields.nonce, 32);
  header.set(fields.plaintextHash, 44);
  view.setUint32(76, fields.ciphertextLength);
  return header;
}

async function deriveObjectKey(masterKey: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    toBufferSource(masterKey),
    'HKDF',
    false,
    ['deriveBits']
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toBufferSource(salt),
      info: toBufferSource(KEY_INFO),
    },
    baseKey,
    256
  );
  return globalThis.crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/**
 * Seals `plaintext` with a key derived from the master key. The header and the
 * caller's context (the logical vault key) are authenticated as AAD, so moving
 * a blob to another key or editing any header field fails decryption.
 */
export async function sealObject(
  masterKey: Uint8Array,
  keyId: Uint8Array,
  context: string,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const salt = randomBytes(SALT_LENGTH);
  const nonce = randomBytes(NONCE_LENGTH);
  const plaintextHash = await sha256(plaintext);
  const header = buildHeader({
    keyId,
    salt,
    nonce,
    plaintextHash,
    ciphertextLength: plaintext.length + TAG_LENGTH,
  });
  const key = await deriveObjectKey(masterKey, salt);
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toBufferSource(nonce),
      additionalData: toBufferSource(concatBytes(header, utf8ToBytes(context))),
      tagLength: 128,
    },
    key,
    toBufferSource(plaintext)
  );
  return concatBytes(header, new Uint8Array(ciphertext));
}

/**
 * Opens an envelope sealed by {@link sealObject} for the same key and context.
 * Every failure is reported as a {@link VaultIntegrityError}: there is no way to
 * distinguish a corrupt blob from a forged one, and both must fail closed.
 */
export async function openObject(
  masterKey: Uint8Array,
  keyId: Uint8Array,
  context: string,
  envelope: Uint8Array
): Promise<Uint8Array> {
  if (envelope.length < HEADER_LENGTH + TAG_LENGTH) {
    throw new VaultIntegrityError('envelope is truncated');
  }

  for (let index = 0; index < ENVELOPE_MAGIC.length; index += 1) {
    if (envelope[index] !== ENVELOPE_MAGIC[index]) {
      throw new VaultIntegrityError('envelope magic does not match');
    }
  }

  const version = envelope[4];
  if (version !== ENVELOPE_VERSION) {
    throw new VaultError('invalid-envelope', `unsupported envelope version ${version}`);
  }
  const algorithm = envelope[5];
  if (algorithm !== ENVELOPE_ALG_AES_256_GCM) {
    throw new VaultError('invalid-envelope', `unsupported envelope algorithm ${algorithm}`);
  }

  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  if (view.getUint16(6) !== 0) {
    throw new VaultIntegrityError('envelope reserved bytes are not zero');
  }

  if (!equalsConstantTime(envelope.subarray(8, 16), keyId)) {
    throw new VaultIntegrityError('envelope was sealed with a different master key');
  }

  const ciphertextLength = view.getUint32(76);
  if (ciphertextLength !== envelope.length - HEADER_LENGTH) {
    throw new VaultIntegrityError('envelope length does not match its header');
  }

  const header = envelope.subarray(0, HEADER_LENGTH);
  const salt = envelope.subarray(16, 32);
  const nonce = envelope.subarray(32, 44);
  const ciphertext = envelope.subarray(HEADER_LENGTH);

  const key = await deriveObjectKey(masterKey, salt);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(nonce),
        additionalData: toBufferSource(concatBytes(header, utf8ToBytes(context))),
        tagLength: 128,
      },
      key,
      toBufferSource(ciphertext)
    );
  } catch (error) {
    throw new VaultIntegrityError('envelope failed authentication', {
      cause: error,
    });
  }

  // The plaintext hash sits inside the AAD, so GCM already proves it matches.
  return new Uint8Array(plaintext);
}
