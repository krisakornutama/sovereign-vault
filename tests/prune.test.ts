import { describe, expect, it } from 'vitest';
import { MemoryBlobStore, Vault } from '../src/index.js';
import type { BlobStore } from '../src/index.js';

const KEY = new Uint8Array(32).fill(3);
const enc = (value: string) => new TextEncoder().encode(value);

async function* pieces(...values: string[]): AsyncGenerator<Uint8Array> {
  for (const value of values) yield enc(value);
}

/** Fails the first index commit so its chunk blobs are left behind. */
class FlakyIndexStore implements BlobStore {
  private readonly inner = new MemoryBlobStore();
  failIndexWrites = false;

  async read(path: string) {
    return this.inner.read(path);
  }

  async write(path: string, bytes: Uint8Array) {
    if (this.failIndexWrites && path === 'index') throw new Error('simulated crash');
    await this.inner.write(path, bytes);
  }

  async remove(path: string) {
    return this.inner.remove(path);
  }

  async list(prefix: string) {
    return this.inner.list(prefix);
  }
}

describe('pruneOrphans', () => {
  it('sweeps the chunks a crashed write left behind and keeps live data readable', async () => {
    const store = new FlakyIndexStore();
    const vault = await Vault.open({ store, masterKey: KEY });
    await vault.put('note/keep', enc('keep me'));

    store.failIndexWrites = true;
    await expect(
      vault.putStream('backup/crash', pieces('aaaabbbb'), { chunkSize: 4 })
    ).rejects.toThrow('simulated crash');
    store.failIndexWrites = false;
    expect(await store.list('chunks/')).toHaveLength(2);

    const reopened = await Vault.open({ store, masterKey: KEY });
    const report = await reopened.pruneOrphans();

    expect(report.paths).toHaveLength(2);
    expect(report.bytes).toBeGreaterThan(0);
    expect(await store.list('chunks/')).toHaveLength(0);
    expect(new TextDecoder().decode(await reopened.get('note/keep'))).toBe('keep me');
    expect(reopened.list().map((entry) => entry.key)).toEqual(['note/keep']);
  });

  it('reports without deleting when dryRun is set', async () => {
    const store = new FlakyIndexStore();
    const vault = await Vault.open({ store, masterKey: KEY });
    await store.write('objects/not-in-index', enc('orphan'));

    const report = await vault.pruneOrphans({ dryRun: true });

    expect(report.paths).toEqual(['objects/not-in-index']);
    expect(report.bytes).toBe(enc('orphan').length);
    expect(await store.read('objects/not-in-index')).not.toBeNull();
  });

  it('never removes a path the index still points at, even when it is missing', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY });
    await vault.putStream('file/big', pieces('aaaabbbb'), { chunkSize: 4 });
    const live = await store.list('chunks/');
    await store.remove(live[0] as string);

    const report = await vault.pruneOrphans();

    expect(report.paths).toEqual([]);
    expect(await store.list('chunks/')).toHaveLength(1);
    expect((await vault.verifyAll()).failures).toHaveLength(1);
  });

  it('is a no-op on an empty vault', async () => {
    const vault = await Vault.open({ store: new MemoryBlobStore(), masterKey: KEY });
    expect(await vault.pruneOrphans()).toEqual({ paths: [], bytes: 0 });
  });
});
