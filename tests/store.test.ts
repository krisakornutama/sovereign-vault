import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FileBlobStore, MemoryBlobStore, VaultError, utf8ToBytes } from '../src/index.js';

const directories: string[] = [];

async function tempDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'sovereign-vault-test-'));
  directories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))
  );
});

describe('MemoryBlobStore', () => {
  it('copies bytes in and out', async () => {
    const store = new MemoryBlobStore();
    const bytes = utf8ToBytes('value');
    await store.write('a/b', bytes);
    bytes[0] = 0x00;

    const read = await store.read('a/b');
    expect(read && new TextDecoder().decode(read)).toBe('value');

    if (!read) throw new Error('missing blob');
    read[0] = 0x01;
    const again = await store.read('a/b');
    expect(again && new TextDecoder().decode(again)).toBe('value');
  });

  it('lists by prefix, removes and reports size', async () => {
    const store = new MemoryBlobStore();
    await store.write('objects/1', utf8ToBytes('1'));
    await store.write('objects/2', utf8ToBytes('2'));
    await store.write('index', utf8ToBytes('i'));

    expect(await store.list('objects/')).toEqual(['objects/1', 'objects/2']);
    expect(await store.list('missing/')).toEqual([]);
    expect(store.size).toBe(3);

    await store.remove('objects/1');
    expect(store.size).toBe(2);
    expect(await store.read('objects/1')).toBeNull();
  });
});

describe('FileBlobStore', () => {
  it('writes, reads, lists and removes objects', async () => {
    const root = await tempDirectory();
    const store = new FileBlobStore(root);

    await store.write('objects/abc', utf8ToBytes('hello'));
    await store.write('objects/def', utf8ToBytes('world'));

    const read = await store.read('objects/abc');
    expect(read && new TextDecoder().decode(read)).toBe('hello');
    expect(await store.list('objects/')).toEqual(['objects/abc', 'objects/def']);
    expect(await store.read('objects/missing')).toBeNull();

    await store.remove('objects/abc');
    expect(await store.list('objects/')).toEqual(['objects/def']);
    await store.remove('objects/abc');
  });

  it('cleans up temporary files after a write', async () => {
    const root = await tempDirectory();
    const store = new FileBlobStore(root);
    await store.write('objects/abc', utf8ToBytes('hello'));

    const entries = await readdir(join(root, 'objects'));
    expect(entries).toEqual(['abc']);
  });

  it('creates the root when listing a fresh store', async () => {
    const root = join(await tempDirectory(), 'nested', 'root');
    const store = new FileBlobStore(root);
    expect(await store.list('')).toEqual([]);
    expect(await readdir(root)).toEqual([]);
  });

  it('rejects paths that escape the root', async () => {
    const store = new FileBlobStore(await tempDirectory());
    for (const path of ['../escape', 'a//b', './a', '', 'a/./b']) {
      await expect(store.read(path)).rejects.toBeInstanceOf(VaultError);
    }
  });

  it('wraps list and remove failures in a store error', async () => {
    const root = await tempDirectory();
    const filePath = join(root, 'not-a-directory');
    await writeFile(filePath, 'occupied');
    const store = new FileBlobStore(filePath);

    await expect(store.list('')).rejects.toMatchObject({ code: 'store' });
    await expect(store.remove('../escape')).rejects.toMatchObject({ code: 'store' });
  });

  it('wraps write failures in a store error', async () => {
    const root = await tempDirectory();
    const filePath = join(root, 'not-a-directory');
    await writeFile(filePath, 'occupied');
    const store = new FileBlobStore(filePath);

    const error = await store
      .write('objects/x', utf8ToBytes('bytes'))
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(VaultError);
    expect((error as VaultError).code).toBe('store');
  });
});
