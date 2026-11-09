import { bytesToUtf8, sha256, toHex, utf8ToBytes } from './bytes.js';
import { KEY_ID_LENGTH, MASTER_KEY_LENGTH, openObject, sealObject } from './envelope.js';
import { VaultError, VaultIntegrityError } from './errors.js';
import type { BlobStore } from './store.js';

export interface VaultEntry {
  readonly key: string;
  /** SHA-256 of the plaintext, hex encoded. */
  readonly hash: string;
  readonly size: number;
  readonly updatedAt: number;
}

export interface VerifyFailure {
  readonly key: string;
  readonly reason: string;
}

export interface VerifyReport {
  readonly checked: number;
  readonly failures: readonly VerifyFailure[];
}

export interface VaultOptions {
  readonly store: BlobStore;
  /** 32 random bytes. Losing it means losing the data; back it up outside the vault. */
  readonly masterKey: Uint8Array;
  readonly clock?: () => number;
}

interface IndexEntry {
  readonly hash: string;
  readonly size: number;
  readonly updatedAt: number;
}

interface VaultIndex {
  readonly version: 1;
  readonly entries: Map<string, IndexEntry>;
}

const INDEX_PATH = 'index';
const INDEX_CONTEXT = '@index';
const OBJECT_PREFIX = 'objects/';
const MAX_KEY_BYTES = 512;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertValidKey(key: string): void {
  if (typeof key !== 'string' || key.trim().length === 0) {
    throw new VaultError('invalid-key', 'vault key must be a non-empty string');
  }
  if (utf8ToBytes(key).length > MAX_KEY_BYTES) {
    throw new VaultError('invalid-key', `vault key must be at most ${MAX_KEY_BYTES} bytes`);
  }
}

function parseIndex(plaintext: Uint8Array): VaultIndex {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToUtf8(plaintext));
  } catch (error) {
    throw new VaultError('corrupt-index', 'vault index is not valid JSON', { cause: error });
  }
  if (!isRecord(parsed) || parsed.version !== 1 || !isRecord(parsed.entries)) {
    throw new VaultError('corrupt-index', 'vault index has an unknown shape');
  }
  const entries = new Map<string, IndexEntry>();
  for (const [key, value] of Object.entries(parsed.entries)) {
    if (
      !isRecord(value) ||
      typeof value.hash !== 'string' ||
      typeof value.size !== 'number' ||
      typeof value.updatedAt !== 'number'
    ) {
      throw new VaultError('corrupt-index', `vault index entry ${key} is malformed`);
    }
    entries.set(key, { hash: value.hash, size: value.size, updatedAt: value.updatedAt });
  }
  return { version: 1, entries };
}

/**
 * Encrypted, tamper-evident key/value store.
 *
 * Every object is sealed with a fresh salt and nonce under a key derived from
 * the master key, and the logical key is authenticated as AAD. A modified,
 * truncated or swapped blob, a wrong master key and a mismatched index all fail
 * closed with {@link VaultIntegrityError} instead of returning wrong bytes.
 *
 * Limitation (M1): the index is not anchored outside the store, so an attacker
 * who can replace every blob with an older consistent snapshot can roll the
 * vault back. Anchoring belongs to the next milestone.
 */
export class Vault {
  private readonly store: BlobStore;
  private readonly masterKey: Uint8Array;
  private readonly keyId: Uint8Array;
  private readonly index: VaultIndex;
  private readonly clock: () => number;
  private tail: Promise<unknown> = Promise.resolve();

  private constructor(
    store: BlobStore,
    masterKey: Uint8Array,
    keyId: Uint8Array,
    index: VaultIndex,
    clock: () => number
  ) {
    this.store = store;
    this.masterKey = masterKey;
    this.keyId = keyId;
    this.index = index;
    this.clock = clock;
  }

  static async open(options: VaultOptions): Promise<Vault> {
    const { store, masterKey } = options;
    if (!(masterKey instanceof Uint8Array) || masterKey.length !== MASTER_KEY_LENGTH) {
      throw new VaultError(
        'invalid-key',
        `master key must be a Uint8Array of ${MASTER_KEY_LENGTH} bytes`
      );
    }
    const keyId = (await sha256(masterKey)).slice(0, KEY_ID_LENGTH);
    const sealedIndex = await store.read(INDEX_PATH);
    const index: VaultIndex = sealedIndex
      ? await openIndex(masterKey, keyId, sealedIndex)
      : { version: 1, entries: new Map() };
    return new Vault(store, new Uint8Array(masterKey), keyId, index, options.clock ?? Date.now);
  }

  list(): VaultEntry[] {
    return [...this.index.entries.entries()]
      .map(([key, entry]) => ({ key, ...entry }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }

  has(key: string): boolean {
    return this.index.entries.has(key);
  }

  async put(key: string, value: Uint8Array): Promise<VaultEntry> {
    assertValidKey(key);
    if (!(value instanceof Uint8Array)) {
      throw new VaultError('invalid-key', 'vault values must be a Uint8Array');
    }
    const plaintext = new Uint8Array(value);
    return this.runExclusive(async () => {
      const sealed = await sealObject(this.masterKey, this.keyId, key, plaintext);
      await this.store.write(await this.objectPath(key), sealed);
      const entry: IndexEntry = {
        hash: toHex(await sha256(plaintext)),
        size: plaintext.length,
        updatedAt: this.clock(),
      };
      this.index.entries.set(key, entry);
      await this.writeIndex();
      return { key, ...entry };
    });
  }

  async get(key: string): Promise<Uint8Array> {
    assertValidKey(key);
    const entry = this.index.entries.get(key);
    if (!entry) {
      throw new VaultError('not-found', `vault has no entry for ${key}`);
    }
    const sealed = await this.store.read(await this.objectPath(key));
    if (!sealed) {
      throw new VaultIntegrityError(`stored object for ${key} is missing`);
    }
    const plaintext = await this.openSealed(key, sealed);
    const hash = toHex(await sha256(plaintext));
    if (hash !== entry.hash || plaintext.length !== entry.size) {
      throw new VaultIntegrityError(`stored object for ${key} does not match the index`);
    }
    return plaintext;
  }

  async delete(key: string): Promise<boolean> {
    assertValidKey(key);
    return this.runExclusive(async () => {
      if (!this.index.entries.has(key)) return false;
      await this.store.remove(await this.objectPath(key));
      this.index.entries.delete(key);
      await this.writeIndex();
      return true;
    });
  }

  /** Re-opens every object and reports failures instead of throwing. */
  async verifyAll(): Promise<VerifyReport> {
    const keys = [...this.index.entries.keys()];
    const failures: VerifyFailure[] = [];
    for (const key of keys) {
      try {
        await this.get(key);
      } catch (error) {
        failures.push({ key, reason: error instanceof Error ? error.message : String(error) });
      }
    }
    return { checked: keys.length, failures };
  }

  private async objectPath(key: string): Promise<string> {
    return `${OBJECT_PREFIX}${toHex(await sha256(utf8ToBytes(key)))}`;
  }

  private async openSealed(key: string, sealed: Uint8Array): Promise<Uint8Array> {
    try {
      return await openObject(this.masterKey, this.keyId, key, sealed);
    } catch (error) {
      if (error instanceof VaultIntegrityError) throw error;
      throw new VaultIntegrityError(`stored object for ${key} could not be opened`, {
        cause: error,
      });
    }
  }

  private async writeIndex(): Promise<void> {
    const snapshot = JSON.stringify({
      version: this.index.version,
      entries: Object.fromEntries(this.index.entries),
    });
    const sealed = await sealObject(
      this.masterKey,
      this.keyId,
      INDEX_CONTEXT,
      utf8ToBytes(snapshot)
    );
    await this.store.write(INDEX_PATH, sealed);
  }

  /** Serializes whole operations so interleaved writes cannot desync blob and index. */
  private runExclusive<T>(task: () => Promise<T>): Promise<T> {
    const run = this.tail.then(task, task);
    this.tail = run;
    return run;
  }
}

async function openIndex(
  masterKey: Uint8Array,
  keyId: Uint8Array,
  sealed: Uint8Array
): Promise<VaultIndex> {
  let plaintext: Uint8Array;
  try {
    plaintext = await openObject(masterKey, keyId, INDEX_CONTEXT, sealed);
  } catch (error) {
    throw new VaultError('corrupt-index', 'vault index failed authentication', { cause: error });
  }
  return parseIndex(plaintext);
}
