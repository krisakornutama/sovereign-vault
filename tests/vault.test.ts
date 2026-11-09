import { describe, expect, it } from 'vitest';
import {
  MemoryBlobStore,
  Vault,
  VaultError,
  VaultIntegrityError,
  bytesToUtf8,
  randomBytes,
  sealObject,
  sha256,
  toHex,
  utf8ToBytes,
} from '../src/index.js';
import type { BlobStore } from '../src/index.js';

const MASTER_KEY = randomBytes(32);

async function openVault(
  store: BlobStore = new MemoryBlobStore(),
  masterKey: Uint8Array = MASTER_KEY
): Promise<Vault> {
  return Vault.open({ store, masterKey });
}

async function captureError(promise: Promise<unknown>): Promise<VaultError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(VaultError);
    return error as VaultError;
  }
  throw new Error('expected the promise to reject');
}

async function objectPath(key: string): Promise<string> {
  return `objects/${toHex(await sha256(utf8ToBytes(key)))}`;
}

async function objectBytes(store: MemoryBlobStore, key: string): Promise<Uint8Array> {
  const bytes = await store.read(await objectPath(key));
  if (!bytes) throw new Error(`missing object for ${key}`);
  return bytes;
}

async function keyId(): Promise<Uint8Array> {
  return (await sha256(MASTER_KEY)).slice(0, 8);
}

async function sealIndex(store: BlobStore, json: string): Promise<void> {
  const sealed = await sealObject(MASTER_KEY, await keyId(), '@index', utf8ToBytes(json));
  await store.write('index', sealed);
}

describe('Vault round trips', () => {
  it('stores and returns UTF-8 and binary values', async () => {
    const vault = await openVault();
    const thai = utf8ToBytes('สวัสดี Sovereign Vault');
    const binary = new Uint8Array([0, 1, 2, 250, 251, 252]);

    const entry = await vault.put('note/thai', thai);
    await vault.put('blob/binary', binary);

    expect(bytesToUtf8(await vault.get('note/thai'))).toBe('สวัสดี Sovereign Vault');
    expect(await vault.get('blob/binary')).toEqual(binary);
    expect(entry.size).toBe(thai.length);
    expect(entry.hash).toHaveLength(64);
    expect(vault.has('note/thai')).toBe(true);
    expect(vault.has('note/missing')).toBe(false);
  });

  it('stores empty values and keeps list sorted', async () => {
    const vault = await openVault();
    await vault.put('b-key', utf8ToBytes('b'));
    await vault.put('a-key', new Uint8Array());

    expect((await vault.get('a-key')).length).toBe(0);
    expect(vault.list().map((entry) => entry.key)).toEqual(['a-key', 'b-key']);
  });

  it('replaces an existing key without leaving a stale entry', async () => {
    const vault = await openVault();
    const first = await vault.put('config/theme', utf8ToBytes('dark'));
    const second = await vault.put('config/theme', utf8ToBytes('light'));

    expect(vault.list()).toHaveLength(1);
    expect(bytesToUtf8(await vault.get('config/theme'))).toBe('light');
    expect(second.hash).not.toBe(first.hash);
  });

  it('keeps the index and objects across a reopen', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.put('note/hello', utf8ToBytes('persisted'));

    const reopened = await openVault(store);
    expect(bytesToUtf8(await reopened.get('note/hello'))).toBe('persisted');
    expect(reopened.list().map((entry) => entry.key)).toEqual(['note/hello']);
  });

  it('records timestamps from the injected clock', async () => {
    let now = 100;
    const store = new MemoryBlobStore();
    const vault = await Vault.open({
      store,
      masterKey: MASTER_KEY,
      clock: () => {
        now += 5;
        return now;
      },
    });

    const entry = await vault.put('tick', utf8ToBytes('tock'));
    expect(entry.updatedAt).toBe(105);
  });

  it('serializes concurrent writes', async () => {
    const vault = await openVault();
    const keys = ['k1', 'k2', 'k3', 'k4', 'k5'];
    await Promise.all(keys.map((key) => vault.put(key, utf8ToBytes(`value-${key}`))));

    expect(vault.list()).toHaveLength(keys.length);
    for (const key of keys) {
      expect(bytesToUtf8(await vault.get(key))).toBe(`value-${key}`);
    }
  });

  it('deletes entries and reports whether anything was removed', async () => {
    const vault = await openVault();
    await vault.put('temp', utf8ToBytes('x'));

    expect(await vault.delete('temp')).toBe(true);
    expect(await vault.delete('temp')).toBe(false);
    expect(vault.list()).toEqual([]);
    await expect(vault.get('temp')).rejects.toMatchObject({
      code: 'not-found',
    });
  });
});

describe('Vault validation', () => {
  it('rejects blank, oversized and non-byte values', async () => {
    const vault = await openVault();
    expect((await captureError(vault.put('   ', utf8ToBytes('x')))).code).toBe('invalid-key');
    expect((await captureError(vault.put('a'.repeat(513), utf8ToBytes('x')))).code).toBe(
      'invalid-key'
    );
    expect((await captureError(vault.put('k', 'text' as unknown as Uint8Array))).code).toBe(
      'invalid-key'
    );
    expect((await captureError(vault.get(''))).code).toBe('invalid-key');
    expect((await captureError(vault.delete(''))).code).toBe('invalid-key');
  });

  it('rejects master keys of the wrong type or length', async () => {
    const store = new MemoryBlobStore();
    expect((await captureError(Vault.open({ store, masterKey: randomBytes(31) }))).code).toBe(
      'invalid-key'
    );
    expect(
      (
        await captureError(
          Vault.open({
            store,
            masterKey: 'not-a-key' as unknown as Uint8Array,
          })
        )
      ).code
    ).toBe('invalid-key');
  });

  it('rejects a wrong master key before touching ciphertext', async () => {
    const store = new MemoryBlobStore();
    await (await openVault(store)).put('note/hello', utf8ToBytes('secret'));

    const error = await captureError(openVault(store, randomBytes(32)));
    expect(error.code).toBe('corrupt-index');
  });
});

describe('Vault tamper detection', () => {
  it('reports a missing object blob', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.put('note/hello', utf8ToBytes('secret'));
    await store.remove(await objectPath('note/hello'));

    expect(await captureError(vault.get('note/hello'))).toBeInstanceOf(VaultIntegrityError);
  });

  it('reports flipped ciphertext bytes', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.put('note/hello', utf8ToBytes('secret'));
    const bytes = await objectBytes(store, 'note/hello');
    bytes[bytes.length - 1] ^= 0xff;
    await store.write(await objectPath('note/hello'), bytes);

    const error = await captureError(vault.get('note/hello'));
    expect(error).toBeInstanceOf(VaultIntegrityError);
    expect(error.code).toBe('integrity');
  });

  it('reports header edits, truncation and length lies', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    const path = await objectPath('note/hello');

    const mutations: Array<(bytes: Uint8Array) => void> = [
      (bytes) => {
        bytes[4] = 9;
      },
      (bytes) => {
        bytes[5] = 9;
      },
      (bytes) => {
        bytes[6] = 1;
      },
      (bytes) => {
        bytes[8] ^= 0xff;
      },
      (bytes) => {
        bytes[79] = 0xff;
      },
    ];

    for (const mutate of mutations) {
      await vault.put('note/hello', utf8ToBytes('secret'));
      const bytes = await objectBytes(store, 'note/hello');
      mutate(bytes);
      await store.write(path, bytes);
      const error = await captureError(vault.get('note/hello'));
      expect(error.code).toBe('integrity');
    }

    await vault.put('note/hello', utf8ToBytes('secret'));
    const truncated = (await objectBytes(store, 'note/hello')).slice(0, 40);
    await store.write(path, truncated);
    expect(await captureError(vault.get('note/hello'))).toBeInstanceOf(VaultIntegrityError);
  });

  it('rejects a blob moved to another key', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.put('alpha', utf8ToBytes('alpha-value'));
    await vault.put('beta', utf8ToBytes('beta-value'));

    await store.write(await objectPath('beta'), await objectBytes(store, 'alpha'));
    expect(await captureError(vault.get('beta'))).toBeInstanceOf(VaultIntegrityError);
  });

  it('rejects an object whose plaintext no longer matches the index', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.put('beta', utf8ToBytes('beta-value'));

    const sealed = await sealObject(MASTER_KEY, await keyId(), 'beta', utf8ToBytes('other-value'));
    await store.write(await objectPath('beta'), sealed);

    const error = await captureError(vault.get('beta'));
    expect(error.message).toMatch(/does not match the index/);
  });

  it('reports every corrupt object from verifyAll without throwing', async () => {
    const store = new MemoryBlobStore();
    const vault = await openVault(store);
    await vault.put('good', utf8ToBytes('fine'));
    await vault.put('bad', utf8ToBytes('broken'));
    const bytes = await objectBytes(store, 'bad');
    bytes[bytes.length - 2] ^= 0x01;
    await store.write(await objectPath('bad'), bytes);

    const report = await vault.verifyAll();
    expect(report.checked).toBe(2);
    expect(report.failures.map((failure) => failure.key)).toEqual(['bad']);
    expect(report.failures[0]?.reason).toMatch(/authentication/);
  });

  it('stringifies non-Error failures in verifyAll', async () => {
    class ThrowingStore extends MemoryBlobStore {
      override async read(path: string): Promise<Uint8Array | null> {
        if (path.startsWith('objects/')) throw 'store exploded';
        return super.read(path);
      }
    }
    const store = new ThrowingStore();
    const vault = await openVault(store);
    await vault.put('note', utf8ToBytes('value'));

    const report = await vault.verifyAll();
    expect(report.failures).toEqual([{ key: 'note', reason: 'store exploded' }]);
  });
});

describe('Vault index handling', () => {
  it('rejects an index that fails authentication', async () => {
    const store = new MemoryBlobStore();
    await (await openVault(store)).put('note', utf8ToBytes('value'));
    const sealed = await store.read('index');
    if (!sealed) throw new Error('missing index');
    sealed[sealed.length - 1] ^= 0xff;
    await store.write('index', sealed);

    expect((await captureError(openVault(store))).code).toBe('corrupt-index');
  });

  it('rejects malformed index payloads', async () => {
    const payloads = [
      'not json',
      '[]',
      '{"version":2,"entries":{}}',
      '{"version":1,"entries":[]}',
      '{"version":1,"entries":{"a":{}}}',
    ];

    for (const payload of payloads) {
      const store = new MemoryBlobStore();
      await sealIndex(store, payload);
      const error = await captureError(openVault(store));
      expect(error.code).toBe('corrupt-index');
    }
  });

  it('loads an empty index when the store is fresh', async () => {
    const vault = await openVault(new MemoryBlobStore());
    expect(vault.list()).toEqual([]);
    expect(await vault.verifyAll()).toEqual({ checked: 0, failures: [] });
  });
});
