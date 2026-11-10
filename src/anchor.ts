import { bytesToUtf8, sha256, toHex, utf8ToBytes } from './bytes.js';
import { VaultError, VaultIntegrityError, VaultRollbackError } from './errors.js';
import type { BlobStore } from './store.js';

/** Chain hash of the entry before the first anchor. */
export const ANCHOR_GENESIS = '0'.repeat(64);

const ROOT_PATTERN = /^[0-9a-f]{64}$/;
const ANCHOR_PREFIX = 'anchors/';

export interface AnchorEntry {
  /** 1-based position in the chain. */
  readonly seq: number;
  /** Hex vault root this checkpoint vouches for. */
  readonly root: string;
  /** `chain` of the previous entry, or {@link ANCHOR_GENESIS}. */
  readonly prev: string;
  readonly at: number;
  /** SHA-256 over the entry fields, chaining it to its predecessor. */
  readonly chain: string;
}

export interface AnchorHead {
  readonly seq: number;
  readonly root: string;
  readonly chain: string;
}

export interface AnchorReport {
  readonly entries: number;
  readonly head: AnchorHead | null;
}

export interface AnchorCheck {
  /** Root the vault currently computes. */
  readonly root: string;
  /** Root of the newest anchor entry, if the log has one. */
  readonly anchored: string | null;
  readonly seq: number | null;
}

/**
 * Append-only, hash-chained record of vault roots.
 *
 * The vault root is a hash of the whole index, so any rollback of the vault
 * changes it. Point the log at storage the vault attacker cannot rewrite (a
 * second directory, a synced folder, a remote witness) and a rollback becomes
 * visible even when every vault blob was replaced with an older consistent set.
 */
export interface AnchorLog {
  head(): Promise<AnchorHead | null>;
  append(root: string, at: number): Promise<AnchorEntry>;
  entries(): Promise<AnchorEntry[]>;
  verify(): Promise<AnchorReport>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertRoot(root: string, label: string): void {
  if (!ROOT_PATTERN.test(root)) {
    throw new VaultError('invalid-root', `${label} must be a lowercase hex SHA-256 digest`);
  }
}

function entryPayload(seq: number, root: string, prev: string, at: number): Uint8Array {
  return utf8ToBytes(JSON.stringify({ seq, root, prev, at }));
}

async function chainOf(seq: number, root: string, prev: string, at: number): Promise<string> {
  return toHex(await sha256(entryPayload(seq, root, prev, at)));
}

async function buildEntry(
  seq: number,
  root: string,
  prev: string,
  at: number
): Promise<AnchorEntry> {
  assertRoot(root, 'anchor root');
  return { seq, root, prev, at, chain: await chainOf(seq, root, prev, at) };
}

function parseEntry(bytes: Uint8Array): AnchorEntry {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToUtf8(bytes));
  } catch (error) {
    throw new VaultError('corrupt-anchor', 'anchor entry is not valid JSON', { cause: error });
  }
  if (
    !isRecord(parsed) ||
    typeof parsed.seq !== 'number' ||
    !Number.isInteger(parsed.seq) ||
    parsed.seq < 1 ||
    typeof parsed.root !== 'string' ||
    typeof parsed.prev !== 'string' ||
    typeof parsed.at !== 'number' ||
    typeof parsed.chain !== 'string'
  ) {
    throw new VaultError('corrupt-anchor', 'anchor entry has an unknown shape');
  }
  return {
    seq: parsed.seq,
    root: parsed.root,
    prev: parsed.prev,
    at: parsed.at,
    chain: parsed.chain,
  };
}

async function verifyChain(entries: readonly AnchorEntry[]): Promise<void> {
  let prev = ANCHOR_GENESIS;
  for (const [index, entry] of entries.entries()) {
    if (entry.seq !== index + 1) {
      throw new VaultError('corrupt-anchor', `anchor sequence skips at entry ${index + 1}`);
    }
    if (entry.prev !== prev) {
      throw new VaultIntegrityError(`anchor ${entry.seq} does not chain to its predecessor`);
    }
    const expected = await chainOf(entry.seq, entry.root, entry.prev, entry.at);
    if (entry.chain !== expected) {
      throw new VaultIntegrityError(`anchor ${entry.seq} fails its own hash`);
    }
    prev = entry.chain;
  }
}

/** Shared append/read logic; storage and process boundaries live in subclasses. */
abstract class ChainedAnchorLog implements AnchorLog {
  abstract entries(): Promise<AnchorEntry[]>;
  protected abstract persist(entry: AnchorEntry): Promise<void>;

  async head(): Promise<AnchorHead | null> {
    const entries = await this.entries();
    const last = entries.at(-1);
    return last ? { seq: last.seq, root: last.root, chain: last.chain } : null;
  }

  async append(root: string, at: number): Promise<AnchorEntry> {
    const entries = await this.entries();
    const last = entries.at(-1);
    await verifyChain(entries);
    const entry = await buildEntry((last?.seq ?? 0) + 1, root, last?.chain ?? ANCHOR_GENESIS, at);
    await this.persist(entry);
    return entry;
  }

  async verify(): Promise<AnchorReport> {
    const entries = await this.entries();
    await verifyChain(entries);
    const last = entries.at(-1);
    return {
      entries: entries.length,
      head: last ? { seq: last.seq, root: last.root, chain: last.chain } : null,
    };
  }
}

export class MemoryAnchorLog extends ChainedAnchorLog {
  private readonly chain: AnchorEntry[] = [];

  async entries(): Promise<AnchorEntry[]> {
    return this.chain.map((entry) => ({ ...entry }));
  }

  protected async persist(entry: AnchorEntry): Promise<void> {
    this.chain.push({ ...entry });
  }
}

/**
 * Anchors stored as one blob per entry, so the log is append-only even on a
 * plain key/value store: nothing is ever rewritten, only added.
 */
export class BlobAnchorLog extends ChainedAnchorLog {
  private readonly store: BlobStore;

  constructor(store: BlobStore) {
    super();
    this.store = store;
  }

  async entries(): Promise<AnchorEntry[]> {
    const paths = await this.store.list(ANCHOR_PREFIX);
    const entries: AnchorEntry[] = [];
    for (const path of paths) {
      const bytes = await this.store.read(path);
      if (!bytes) continue;
      entries.push(parseEntry(bytes));
    }
    return entries;
  }

  protected async persist(entry: AnchorEntry): Promise<void> {
    const name = String(entry.seq).padStart(12, '0');
    await this.store.write(`${ANCHOR_PREFIX}${name}.json`, utf8ToBytes(JSON.stringify(entry)));
  }
}

/**
 * Compares an externally pinned root with the vault root and the newest anchor.
 * Throws {@link VaultRollbackError} when the local state is older than either.
 */
export async function verifyAnchorRoot(
  anchor: AnchorLog,
  root: string,
  expectedRoot?: string
): Promise<AnchorCheck> {
  assertRoot(root, 'vault root');
  if (expectedRoot !== undefined) assertRoot(expectedRoot, 'pinned root');
  const report = await anchor.verify();
  const head = report.head;

  if (expectedRoot !== undefined && root !== expectedRoot) {
    throw new VaultRollbackError(
      `vault root ${root} does not match the pinned root ${expectedRoot}; the store was rolled back`
    );
  }
  if (head && head.root !== root) {
    throw new VaultRollbackError(
      `vault root ${root} is behind anchor ${head.seq} (${head.root}); the store was rolled back`
    );
  }
  return { root, anchored: head?.root ?? null, seq: head?.seq ?? null };
}
