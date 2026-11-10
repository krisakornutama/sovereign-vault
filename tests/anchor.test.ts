import { describe, expect, it } from 'vitest';
import {
  ANCHOR_GENESIS,
  BlobAnchorLog,
  MemoryAnchorLog,
  MemoryBlobStore,
  Vault,
  VaultError,
  VaultIntegrityError,
  VaultRollbackError,
  randomBytes,
  sha256,
  toHex,
  utf8ToBytes,
  verifyAnchorRoot,
} from '../src/index.js';

const MASTER_KEY = randomBytes(32);
const ROOT_A = 'a'.repeat(64);
const ROOT_B = 'b'.repeat(64);

async function objectPath(key: string): Promise<string> {
  return `objects/${toHex(await sha256(utf8ToBytes(key)))}`;
}

describe('MemoryAnchorLog', () => {
  it('chains entries from genesis', async () => {
    const log = new MemoryAnchorLog();
    expect(await log.head()).toBeNull();

    const first = await log.append(ROOT_A, 100);
    const second = await log.append(ROOT_B, 200);

    expect(first).toMatchObject({ seq: 1, root: ROOT_A, prev: ANCHOR_GENESIS });
    expect(second).toMatchObject({ seq: 2, root: ROOT_B, prev: first.chain });
    expect(second.chain).not.toBe(first.chain);
    expect(await log.head()).toEqual({ seq: 2, root: ROOT_B, chain: second.chain });
    expect(await log.verify()).toEqual({
      entries: 2,
      head: { seq: 2, root: ROOT_B, chain: second.chain },
    });
  });

  it('copies entries instead of exposing its array', async () => {
    const log = new MemoryAnchorLog();
    await log.append(ROOT_A, 1);
    const [entry] = await log.entries();
    (entry as { root: string }).root = ROOT_B;

    expect((await log.head())?.root).toBe(ROOT_A);
  });

  it('rejects roots that are not hex digests', async () => {
    const log = new MemoryAnchorLog();
    await expect(log.append('not-a-root', 1)).rejects.toMatchObject({ code: 'invalid-root' });
    await expect(verifyAnchorRoot(log, ROOT_A, 'xyz')).rejects.toMatchObject({
      code: 'invalid-root',
    });
  });

  it('rejects a root older than the pin', async () => {
    await expect(verifyAnchorRoot(new MemoryAnchorLog(), ROOT_A, ROOT_B)).rejects.toBeInstanceOf(
      VaultRollbackError
    );
  });

  it('reports an empty log without throwing', async () => {
    const check = await verifyAnchorRoot(new MemoryAnchorLog(), ROOT_A);
    expect(check).toEqual({ root: ROOT_A, anchored: null, seq: null });
  });
});

describe('BlobAnchorLog', () => {
  it('persists entries as append-only blobs', async () => {
    const store = new MemoryBlobStore();
    const first = new BlobAnchorLog(store);
    await first.append(ROOT_A, 10);
    await first.append(ROOT_B, 20);

    const reopened = new BlobAnchorLog(store);
    expect(await reopened.head()).toMatchObject({ seq: 2, root: ROOT_B });
    expect((await reopened.entries()).map((entry) => entry.seq)).toEqual([1, 2]);
    expect(await store.list('anchors/')).toHaveLength(2);
  });

  it('continues the chain across instances', async () => {
    const store = new MemoryBlobStore();
    const first = await new BlobAnchorLog(store).append(ROOT_A, 10);
    const second = await new BlobAnchorLog(store).append(ROOT_B, 20);
    expect(second.prev).toBe(first.chain);
  });

  it('detects an edited entry', async () => {
    const store = new MemoryBlobStore();
    const log = new BlobAnchorLog(store);
    await log.append(ROOT_A, 10);
    const original = await log.head();
    if (!original) throw new Error('missing anchor');
    await store.write(
      'anchors/000000000001.json',
      utf8ToBytes(
        JSON.stringify({
          seq: 1,
          root: ROOT_B,
          prev: ANCHOR_GENESIS,
          at: 10,
          chain: original.chain,
        })
      )
    );

    await expect(log.verify()).rejects.toBeInstanceOf(VaultIntegrityError);
  });

  it('detects a deleted entry in the middle of the chain', async () => {
    const store = new MemoryBlobStore();
    const log = new BlobAnchorLog(store);
    await log.append(ROOT_A, 10);
    await log.append(ROOT_B, 20);
    await store.remove('anchors/000000000001.json');

    const error = await log.verify().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(VaultError);
    expect((error as VaultError).code).toBe('corrupt-anchor');
  });

  it('detects an entry that does not chain to its predecessor', async () => {
    const store = new MemoryBlobStore();
    const log = new BlobAnchorLog(store);
    await log.append(ROOT_A, 10);
    await log.append(ROOT_B, 20);

    const entry = { seq: 2, root: ROOT_B, prev: ANCHOR_GENESIS, at: 20 };
    const chain = toHex(await sha256(utf8ToBytes(JSON.stringify(entry))));
    await store.write(
      'anchors/000000000002.json',
      utf8ToBytes(JSON.stringify({ ...entry, chain }))
    );

    await expect(log.verify()).rejects.toBeInstanceOf(VaultIntegrityError);
  });

  it('rejects malformed entries', async () => {
    const store = new MemoryBlobStore();
    await store.write('anchors/000000000001.json', utf8ToBytes('not json'));
    await expect(new BlobAnchorLog(store).verify()).rejects.toMatchObject({
      code: 'corrupt-anchor',
    });

    const other = new MemoryBlobStore();
    await other.write('anchors/000000000001.json', utf8ToBytes(JSON.stringify({ seq: 2 })));
    await expect(new BlobAnchorLog(other).verify()).rejects.toMatchObject({
      code: 'corrupt-anchor',
    });
  });

  it('ignores a listed path that disappeared', async () => {
    const store = new MemoryBlobStore();
    const log = new BlobAnchorLog(store);
    await log.append(ROOT_A, 10);
    store.read = async () => null;
    expect(await log.head()).toBeNull();
  });
});

describe('vault roots', () => {
  it('has a stable root across reopens and changes on write', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });
    const empty = await vault.root();
    expect(empty).toMatch(/^[0-9a-f]{64}$/);

    await vault.put('note', utf8ToBytes('hello'));
    const written = await vault.root();
    expect(written).not.toBe(empty);

    const reopened = await Vault.open({ store, masterKey: MASTER_KEY });
    expect(await reopened.root()).toBe(written);
  });

  it('opens only when the pinned root matches', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });
    await vault.put('note', utf8ToBytes('hello'));
    const root = await vault.root();

    const pinned = await Vault.open({ store, masterKey: MASTER_KEY, expectedRoot: root });
    expect(await pinned.root()).toBe(root);

    await expect(
      Vault.open({ store, masterKey: MASTER_KEY, expectedRoot: 'c'.repeat(64) })
    ).rejects.toBeInstanceOf(VaultRollbackError);
  });

  it('refuses a pinned root when the store is empty', async () => {
    await expect(
      Vault.open({ store: new MemoryBlobStore(), masterKey: MASTER_KEY, expectedRoot: ROOT_A })
    ).rejects.toBeInstanceOf(VaultRollbackError);
  });
});

describe('rollback detection with an anchor', () => {
  it('accepts a vault that matches its newest anchor', async () => {
    const store = new MemoryBlobStore();
    const anchors = new MemoryAnchorLog();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });
    await vault.put('note', utf8ToBytes('one'));
    const entry = await vault.anchorNow(anchors, 1000);

    expect(entry.root).toBe(await vault.root());
    expect(await vault.verifyAnchor(anchors)).toEqual({
      root: entry.root,
      anchored: entry.root,
      seq: 1,
    });
  });

  it('rejects a store restored to an older state', async () => {
    const store = new MemoryBlobStore();
    const anchors = new MemoryAnchorLog();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });

    await vault.put('note', utf8ToBytes('one'));
    await vault.anchorNow(anchors, 1000);
    const oldIndex = await store.read('index');

    await vault.put('note', utf8ToBytes('two'));
    await vault.anchorNow(anchors, 2000);

    if (!oldIndex) throw new Error('missing index');
    await store.write('index', oldIndex);
    await store.remove(await objectPath('note'));

    const rolledBack = await Vault.open({ store, masterKey: MASTER_KEY });
    await expect(rolledBack.verifyAnchor(anchors)).rejects.toBeInstanceOf(VaultRollbackError);
  });

  it('rejects a pinned root after a rollback', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: MASTER_KEY });
    await vault.put('a', utf8ToBytes('1'));
    const first = await vault.root();
    await vault.put('b', utf8ToBytes('2'));
    expect(await vault.root()).not.toBe(first);

    await expect(
      Vault.open({ store, masterKey: MASTER_KEY, expectedRoot: first })
    ).rejects.toBeInstanceOf(VaultRollbackError);
  });
});
