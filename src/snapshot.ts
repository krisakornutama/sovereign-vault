import { bytesToUtf8, sha256, toHex, utf8ToBytes } from './bytes.js';
import { VaultError, VaultIntegrityError } from './errors.js';
import type { Vault, VaultEntry } from './vault.js';

const SNAPSHOT_VERSION = 1;
const SNAPSHOT_PREFIX = 'snapshot/';

interface SnapshotFile {
  readonly version: number;
  readonly checksum: string;
  readonly data: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Serializes any JSON-representable state into a versioned, checksummed blob.
 * The checksum detects truncated or edited snapshots before they are restored.
 */
export async function encodeSnapshot(data: unknown): Promise<Uint8Array> {
  const encoded: unknown = JSON.stringify(data);
  if (typeof encoded !== 'string') {
    throw new VaultError('invalid-key', 'snapshot data must be JSON serializable');
  }
  const json = encoded;
  const checksum = toHex(await sha256(utf8ToBytes(json)));
  const file: SnapshotFile = { version: SNAPSHOT_VERSION, checksum, data };
  return utf8ToBytes(JSON.stringify(file));
}

export async function decodeSnapshot<T>(bytes: Uint8Array): Promise<T> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToUtf8(bytes));
  } catch (error) {
    throw new VaultError('invalid-envelope', 'snapshot is not valid JSON', {
      cause: error,
    });
  }
  if (
    !isRecord(parsed) ||
    parsed.version !== SNAPSHOT_VERSION ||
    typeof parsed.checksum !== 'string' ||
    !Object.hasOwn(parsed, 'data')
  ) {
    throw new VaultError('invalid-envelope', 'snapshot header is invalid');
  }
  const json = JSON.stringify(parsed.data);
  const checksum = toHex(await sha256(utf8ToBytes(json)));
  if (checksum !== parsed.checksum) {
    throw new VaultIntegrityError('snapshot checksum does not match its data');
  }
  return parsed.data as T;
}

/** Stores a snapshot under `snapshot/<name>` in the vault. */
export async function saveSnapshot(vault: Vault, name: string, data: unknown): Promise<VaultEntry> {
  return vault.put(`${SNAPSHOT_PREFIX}${name}`, await encodeSnapshot(data));
}

/** Loads a snapshot, or `null` when the name was never saved. */
export async function loadSnapshot<T>(vault: Vault, name: string): Promise<T | null> {
  const key = `${SNAPSHOT_PREFIX}${name}`;
  if (!vault.has(key)) return null;
  return decodeSnapshot<T>(await vault.get(key));
}
