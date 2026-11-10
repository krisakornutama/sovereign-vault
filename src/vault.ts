import { verifyAnchorRoot } from './anchor.js';
import type { AnchorCheck, AnchorEntry, AnchorLog } from './anchor.js';
import { bytesToUtf8, sha256, toHex, utf8ToBytes } from './bytes.js';
import {
  KEY_ID_LENGTH,
  MASTER_KEY_LENGTH,
  envelopeKeyId,
  openObject,
  sealObject,
} from './envelope.js';
import { VaultError, VaultIntegrityError, VaultRollbackError } from './errors.js';
import { Keyring } from './keyring.js';
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
  readonly masterKey?: Uint8Array;
  /** Several keys (rotation / several devices). Pass this instead of `masterKey`. */
  readonly keyring?: Keyring;
  /** Optional root held outside the store; any older state fails to open. */
  readonly expectedRoot?: string;
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

function keyIdBytes(id: string): Uint8Array {
  const bytes = new Uint8Array(KEY_ID_LENGTH);
  for (let index = 0; index < KEY_ID_LENGTH; index += 1) {
    bytes[index] = Number.parseInt(id.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function canonicalIndexJson(index: VaultIndex): string {
  const entries = [...index.entries.entries()].sort(([a], [b]) => a.localeCompare(b));
  return JSON.stringify({ version: index.version, entries: Object.fromEntries(entries) });
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
 * one of the keyring's keys, and the logical key is authenticated as AAD. A
 * modified, truncated or swapped blob, a wrong key and a mismatched index all
 * fail closed with {@link VaultIntegrityError} instead of returning wrong bytes.
 *
 * The keyring makes rotation possible: new writes use the active key, older
 * objects stay readable through their own key, `rekey()` re-seals everything
 * under the active key, and `revokeKey()` refuses to drop a key that still
 * seals data.
 */
export class Vault {
  private readonly store: BlobStore;
  private readonly keyring: Keyring;
  private readonly index: VaultIndex;
  private readonly clock: () => number;
  private tail: Promise<unknown> = Promise.resolve();

  private constructor(store: BlobStore, keyring: Keyring, index: VaultIndex, clock: () => number) {
    this.store = store;
    this.keyring = keyring;
    this.index = index;
    this.clock = clock;
  }

  static async open(options: VaultOptions): Promise<Vault> {
    const { store, masterKey, keyring: providedKeyring } = options;
    if (providedKeyring !== undefined && masterKey !== undefined) {
      throw new VaultError('invalid-key', 'pass either masterKey or keyring, not both');
    }
    let keyring: Keyring;
    if (providedKeyring !== undefined) {
      keyring = providedKeyring;
    } else if (masterKey !== undefined) {
      if (!(masterKey instanceof Uint8Array) || masterKey.length !== MASTER_KEY_LENGTH) {
        throw new VaultError(
          'invalid-key',
          `master key must be a Uint8Array of ${MASTER_KEY_LENGTH} bytes`
        );
      }
      keyring = await Keyring.create([{ key: masterKey, active: true }]);
    } else {
      throw new VaultError('invalid-key', 'Vault.open needs a masterKey or a keyring');
    }

    const sealedIndex = await store.read(INDEX_PATH);
    let index: VaultIndex;
    if (sealedIndex) {
      const id = envelopeKeyId(sealedIndex);
      const key = keyring.keyFor(id);
      if (!key) {
        throw new VaultError(
          'corrupt-index',
          `vault index was sealed with key ${id}, which is not in the keyring`
        );
      }
      index = await openIndex(key, keyIdBytes(id), sealedIndex);
    } else {
      index = { version: 1, entries: new Map() };
    }
    if (options.expectedRoot !== undefined) {
      const root = await rootOf(index);
      if (root !== options.expectedRoot) {
        throw new VaultRollbackError(
          `vault root ${root} does not match the pinned root ${options.expectedRoot}`
        );
      }
    }
    return new Vault(store, keyring, index, options.clock ?? Date.now);
  }

  list(): VaultEntry[] {
    return [...this.index.entries.entries()]
      .map(([key, entry]) => ({ key, ...entry }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }

  has(key: string): boolean {
    return this.index.entries.has(key);
  }

  /** Key ids this vault can read, active first. */
  keyIds(): string[] {
    const active = this.keyring.activeId;
    return [active, ...this.keyring.ids().filter((id) => id !== active)];
  }

  activeKeyId(): string {
    return this.keyring.activeId;
  }

  /**
   * Adds a key and makes it active for new writes. Existing objects stay
   * readable through their old key; call `rekey()` to move them over.
   */
  async rotateKey(key: Uint8Array): Promise<string> {
    return this.runExclusive(async () => {
      const id = await this.keyring.add(key, { activate: true });
      await this.writeIndex();
      return id;
    });
  }

  /**
   * Re-seals every object and the index under the active key.
   * Plaintext (and therefore the vault root) does not change.
   */
  async rekey(): Promise<number> {
    return this.runExclusive(async () => {
      const active = this.activeKey();
      let rekeyed = 0;
      for (const key of this.index.entries.keys()) {
        const path = await this.objectPath(key);
        const sealed = await this.store.read(path);
        if (!sealed) {
          throw new VaultIntegrityError(`stored object for ${key} is missing`);
        }
        const plaintext = await this.openSealed(key, sealed);
        await this.store.write(path, await sealObject(active.key, active.id, key, plaintext));
        rekeyed += 1;
      }
      await this.writeIndex();
      return rekeyed;
    });
  }

  /**
   * Drops a key from the keyring. Refuses the active key and any key that still
   * seals an object, so revocation can never silently destroy readable data.
   */
  async revokeKey(id: string): Promise<boolean> {
    return this.runExclusive(async () => {
      if (id === this.keyring.activeId) {
        throw new VaultError('invalid-key', 'cannot revoke the active key; rotate first');
      }
      if (!this.keyring.has(id)) return false;
      for (const key of this.index.entries.keys()) {
        const sealed = await this.store.read(await this.objectPath(key));
        if (!sealed) {
          throw new VaultIntegrityError(`stored object for ${key} is missing`);
        }
        if (envelopeKeyId(sealed) === id) {
          throw new VaultError(
            'invalid-key',
            `key ${id} still seals ${key}; run rekey() before revoking it`
          );
        }
      }
      return this.keyring.remove(id);
    });
  }

  /** Hash of the canonical index: changes on every put/delete and never otherwise. */
  async root(): Promise<string> {
    return rootOf(this.index);
  }

  /** Appends the current root to an append-only anchor log. */
  async anchorNow(anchor: AnchorLog, at: number = this.clock()): Promise<AnchorEntry> {
    return anchor.append(await this.root(), at);
  }

  /** Fails when this vault is older than the anchor or the pinned root. */
  async verifyAnchor(anchor: AnchorLog, expectedRoot?: string): Promise<AnchorCheck> {
    return verifyAnchorRoot(anchor, await this.root(), expectedRoot);
  }

  async put(key: string, value: Uint8Array): Promise<VaultEntry> {
    assertValidKey(key);
    if (!(value instanceof Uint8Array)) {
      throw new VaultError('invalid-key', 'vault values must be a Uint8Array');
    }
    const plaintext = new Uint8Array(value);
    return this.runExclusive(async () => {
      const active = this.activeKey();
      const sealed = await sealObject(active.key, active.id, key, plaintext);
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

  private activeKey(): { readonly key: Uint8Array; readonly id: Uint8Array } {
    const id = this.keyring.activeId;
    const key = this.keyring.keyFor(id);
    if (!key) {
      throw new VaultError('unknown-key', `active key ${id} is missing from the keyring`);
    }
    return { key, id: keyIdBytes(id) };
  }

  private async objectPath(key: string): Promise<string> {
    return `${OBJECT_PREFIX}${toHex(await sha256(utf8ToBytes(key)))}`;
  }

  private async openSealed(key: string, sealed: Uint8Array): Promise<Uint8Array> {
    try {
      const id = envelopeKeyId(sealed);
      const masterKey = this.keyring.keyFor(id);
      if (!masterKey) {
        // From this vault's point of view the blob is foreign: fail closed the same
        // way a forged or swapped envelope does, but say which key is missing.
        throw new VaultIntegrityError(
          `stored object for ${key} was sealed with key ${id}, which is not in the keyring`
        );
      }
      return await openObject(masterKey, keyIdBytes(id), key, sealed);
    } catch (error) {
      if (error instanceof VaultIntegrityError) throw error;
      throw new VaultIntegrityError(`stored object for ${key} could not be opened`, {
        cause: error,
      });
    }
  }

  private async writeIndex(): Promise<void> {
    const active = this.activeKey();
    const sealed = await sealObject(
      active.key,
      active.id,
      INDEX_CONTEXT,
      utf8ToBytes(canonicalIndexJson(this.index))
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

async function rootOf(index: VaultIndex): Promise<string> {
  return toHex(await sha256(utf8ToBytes(canonicalIndexJson(index))));
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
