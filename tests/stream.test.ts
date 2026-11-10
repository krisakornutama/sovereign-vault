import { describe, expect, it } from 'vitest';
import { MemoryBlobStore, Vault, keyIdOfKey, type VaultError } from '../src/index.js';

const KEY_A = new Uint8Array(32).fill(5);
const KEY_B = new Uint8Array(32).fill(9);
const enc = (value: string) => new TextEncoder().encode(value);

async function* pieces(...values: string[]): AsyncGenerator<Uint8Array> {
  for (const value of values) yield enc(value);
}

async function captureError(task: Promise<unknown>): Promise<VaultError> {
  try {
    await task;
  } catch (error) {
    return error as VaultError;
  }
  throw new Error('expected the task to fail');
}

const openVault = (store = new MemoryBlobStore()) => Vault.open({ store, masterKey: KEY_A });

describe('putStream / getStream', () => {
  it('splits a value into fixed chunks and reads it back in order', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);

    const entry = await vault.putStream('file/big', pieces('abcd', 'efgh', 'ij'), {
      chunkSize: 4,
    });

    expect(entry.size).toBe(10);
    expect(entry.chunks?.map((chunk) => chunk.size)).toEqual([4, 4, 2]);
    expect(await store.list('chunks/')).toHaveLength(3);
    expect(new TextDecoder().decode(await vault.get('file/big'))).toBe('abcdefghij');

    const collected: string[] = [];
    for await (const chunk of vault.getStream('file/big')) {
      collected.push(new TextDecoder().decode(chunk));
    }
    expect(collected).toEqual(['abcd', 'efgh', 'ij']);
  });

  it('handles an empty stream as a zero-length value', async () => {
    const vault = await openVault();
    const entry = await vault.putStream('file/empty', pieces(), { chunkSize: 8 });
    expect(entry.size).toBe(0);
    expect(entry.chunks).toEqual([]);
    expect((await vault.get('file/empty')).length).toBe(0);
  });

  it('yields one chunk for values written with put()', async () => {
    const vault = await openVault();
    await vault.put('file/small', enc('hello'));
    const collected: string[] = [];
    for await (const chunk of vault.getStream('file/small')) {
      collected.push(new TextDecoder().decode(chunk));
    }
    expect(collected).toEqual(['hello']);
  });

  it('removes the previous chunks when a stream is overwritten with fewer', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.putStream('file/big', pieces('aaaabbbb'), { chunkSize: 4 });
    expect(await store.list('chunks/')).toHaveLength(2);

    await vault.putStream('file/big', pieces('cc'), { chunkSize: 4 });
    expect(await store.list('chunks/')).toHaveLength(1);
    expect(new TextDecoder().decode(await vault.get('file/big'))).toBe('cc');
  });

  it('rejects invalid chunk sizes and non-byte chunks', async () => {
    const vault = await openVault();
    for (const chunkSize of [0, -1, 1.5]) {
      expect((await captureError(vault.putStream('file/x', pieces('a'), { chunkSize }))).code).toBe(
        'invalid-key'
      );
    }
    const broken = (async function* brokenSource() {
      yield 'not bytes' as unknown as Uint8Array;
    })();
    expect((await captureError(vault.putStream('file/x', broken))).code).toBe('invalid-key');
  });

  it('stops with an integrity error when a chunk no longer matches the index', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.putStream('file/big', pieces('aaaabbbb'), { chunkSize: 4 });
    const [first] = await store.list('chunks/');
    const bytes = await store.read(first as string);
    bytes![0] ^= 0xff;
    await store.write(first as string, bytes!);

    expect((await captureError(vault.getStream('file/big').next())).code).toBe('integrity');
    expect((await captureError(vault.get('file/big'))).code).toBe('integrity');
    expect((await vault.verifyAll()).failures).toHaveLength(1);
  });

  it('deletes every chunk with the entry', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.putStream('file/big', pieces('aaaabbbb'), { chunkSize: 4 });
    expect(await vault.delete('file/big')).toBe(true);
    expect(await store.list('chunks/')).toHaveLength(0);
    expect((await captureError(vault.get('file/big'))).code).toBe('not-found');
  });

  it('rekeys chunks and refuses to revoke a key still in use by them', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.putStream('file/big', pieces('aaaabbbb'), { chunkSize: 4 });
    await vault.rotateKey(KEY_B);

    const inUse = await captureError(vault.revokeKey(await keyIdOfKey(KEY_A)));
    expect(inUse.code).toBe('invalid-key');

    expect(await vault.rekey()).toBe(2);
    expect(await vault.revokeKey(await keyIdOfKey(KEY_A))).toBe(true);
    expect(new TextDecoder().decode(await vault.get('file/big'))).toBe('aaaabbbb');
  });

  it('refuses to rekey over a missing chunk', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.putStream('file/big', pieces('aaaabbbb'), { chunkSize: 4 });
    const [first] = await store.list('chunks/');
    await store.remove(first as string);
    await vault.rotateKey(KEY_B);
    expect((await captureError(vault.rekey())).code).toBe('integrity');
  });

  it('reports a chunk sealed by a key that is not in the keyring', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.putStream('file/big', pieces('aaaabbbb'), { chunkSize: 4 });
    const [first] = await store.list('chunks/');
    const saved = await store.read(first as string);

    await vault.rotateKey(KEY_B);
    await vault.rekey();
    await vault.revokeKey(await keyIdOfKey(KEY_A));
    await store.write(first as string, saved!);

    const error = await captureError(vault.get('file/big'));
    expect(error.code).toBe('integrity');
    expect(error.message).toMatch(/not in the keyring/);
  });
});
