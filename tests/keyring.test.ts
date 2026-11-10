import { describe, expect, it } from 'vitest';
import { Keyring, MemoryBlobStore, Vault, keyIdOfKey, type VaultError } from '../src/index.js';
import { randomBytes, sha256, toHex } from '../src/bytes.js';

const KEY_A = new Uint8Array(32).fill(1);
const KEY_B = new Uint8Array(32).fill(2);
const KEY_C = new Uint8Array(32).fill(3);

const enc = (value: string) => new TextEncoder().encode(value);
const objectPath = async (key: string) =>
  `objects/${toHex(await sha256(new TextEncoder().encode(key)))}`;
const dec = (value: Uint8Array) => new TextDecoder().decode(value);

async function captureError(task: Promise<unknown>): Promise<VaultError> {
  try {
    await task;
  } catch (error) {
    return error as VaultError;
  }
  throw new Error('expected the task to fail');
}

describe('Keyring', () => {
  it('accepts a single key as active', async () => {
    const keyring = await Keyring.create([{ key: KEY_A }]);
    expect(keyring.size).toBe(1);
    expect(keyring.activeId).toBe(await keyIdOfKey(KEY_A));
  });

  it('needs an explicit active key when several keys are given', async () => {
    expect((await captureError(Keyring.create([{ key: KEY_A }, { key: KEY_B }]))).code).toBe(
      'invalid-key'
    );
    const keyring = await Keyring.create([{ key: KEY_A }, { key: KEY_B, active: true }]);
    expect(keyring.activeId).toBe(await keyIdOfKey(KEY_B));
  });

  it('rejects empty keyrings, short keys and two active keys', async () => {
    expect((await captureError(Keyring.create([]))).code).toBe('invalid-key');
    expect((await captureError(Keyring.create([{ key: new Uint8Array(16) }]))).code).toBe(
      'invalid-key'
    );
    expect(
      (
        await captureError(
          Keyring.create([
            { key: KEY_A, active: true },
            { key: KEY_B, active: true },
          ])
        )
      ).code
    ).toBe('invalid-key');
  });

  it('adds keys idempotently and activates a known key', async () => {
    const keyring = await Keyring.create([{ key: KEY_A }]);
    const idB = await keyring.add(KEY_B);
    expect(keyring.size).toBe(2);
    expect(await keyring.add(KEY_B)).toBe(idB);
    expect(keyring.size).toBe(2);

    keyring.activate(idB);
    expect(keyring.activeId).toBe(idB);
    expect(() => keyring.activate('deadbeefdeadbeef')).toThrow(/no key/);
  });

  it('refuses to remove the active key', async () => {
    const keyring = await Keyring.create([{ key: KEY_A }]);
    expect(() => keyring.remove(keyring.activeId)).toThrow(/cannot revoke the active key/);
  });
});

describe('Vault keys', () => {
  it('rejects ambiguous or missing key configuration', async () => {
    const store = new MemoryBlobStore();
    const keyring = await Keyring.create([{ key: KEY_A }]);
    expect((await captureError(Vault.open({ store, masterKey: KEY_A, keyring }))).code).toBe(
      'invalid-key'
    );
    expect((await captureError(Vault.open({ store }))).code).toBe('invalid-key');
  });

  it('rotates so new writes use the new key while old objects stay readable', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY_A });
    await vault.put('note/old', enc('written with A'));

    const idB = await vault.rotateKey(KEY_B);
    expect(vault.activeKeyId()).toBe(idB);
    expect(vault.keyIds()[0]).toBe(idB);
    await vault.put('note/new', enc('written with B'));

    expect(dec(await vault.get('note/old'))).toBe('written with A');
    expect(dec(await vault.get('note/new'))).toBe('written with B');
    expect((await vault.verifyAll()).failures).toEqual([]);
  });

  it('reopens with an explicit keyring', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY_A });
    await vault.put('note/hello', enc('secret'));
    const idB = await vault.rotateKey(KEY_B);

    const keyring = await Keyring.create([{ key: KEY_A }, { key: KEY_B, active: true }]);
    const reopened = await Vault.open({ store, keyring });
    expect(reopened.activeKeyId()).toBe(idB);
    expect(dec(await reopened.get('note/hello'))).toBe('secret');
  });

  it('rekey() re-seals everything under the active key without changing the root', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY_A });
    await vault.put('a', enc('one'));
    await vault.put('b', enc('two'));
    const root = await vault.root();

    await vault.rotateKey(KEY_B);
    expect(await vault.rekey()).toBe(2);
    expect(await vault.root()).toBe(root);
    expect((await vault.verifyAll()).failures).toEqual([]);

    const onlyB = await Keyring.create([{ key: KEY_B }]);
    const reopened = await Vault.open({ store, keyring: onlyB });
    expect(dec(await reopened.get('a'))).toBe('one');
  });

  it('reports an object sealed by a key that is not in the keyring', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY_A });
    await vault.put('note/hello', enc('secret'));
    const path = await objectPath('note/hello');
    const sealedWithA = await store.read(path);
    expect(sealedWithA).not.toBeNull();

    await vault.rotateKey(KEY_B);
    await vault.rekey();
    expect(await vault.revokeKey(await keyIdOfKey(KEY_A))).toBe(true);

    // Put an old (A-sealed) blob back: the keyring no longer has A.
    await store.write(path, sealedWithA as Uint8Array);
    const error = await captureError(vault.get('note/hello'));
    expect(error.code).toBe('integrity');
    expect(error.message).toMatch(/not in the keyring/);
    expect((await vault.verifyAll()).failures).toHaveLength(1);
  });

  it('refuses to open an index sealed by an unknown key', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY_A });
    await vault.put('note/hello', enc('secret'));

    const onlyB = await Keyring.create([{ key: KEY_B }]);
    const error = await captureError(Vault.open({ store, keyring: onlyB }));
    expect(error.code).toBe('corrupt-index');
  });

  it('revokes only after rekey(): in-use keys are refused, unknown ids are false', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY_A });
    await vault.put('note/hello', enc('secret'));
    const idA = await keyIdOfKey(KEY_A);

    const idB = await vault.rotateKey(KEY_B);
    const inUse = await captureError(vault.revokeKey(idA));
    expect(inUse.code).toBe('invalid-key');
    expect(inUse.message).toMatch(/rekey\(\)/);

    expect(await vault.revokeKey('0000000000000000')).toBe(false);

    await vault.rekey();
    expect(await vault.revokeKey(idA)).toBe(true);
    expect(vault.keyIds()).toEqual([idB]);
    expect(dec(await vault.get('note/hello'))).toBe('secret');
  });

  it('never revokes the active key, even after rotating twice', async () => {
    const vault = await Vault.open({ store: new MemoryBlobStore(), masterKey: KEY_A });
    await vault.rotateKey(KEY_B);
    await vault.rotateKey(KEY_C);
    const active = vault.activeKeyId();
    expect((await captureError(vault.revokeKey(active))).code).toBe('invalid-key');
    expect(vault.keyIds()).toHaveLength(3);
  });

  it('refuses to rotate or rekey over a damaged store', async () => {
    const store = new MemoryBlobStore();
    const vault = await Vault.open({ store, masterKey: KEY_A });
    await vault.put('note/hello', enc('secret'));
    await vault.rotateKey(KEY_B);

    const path = await objectPath('note/hello');
    expect(await store.read(path)).not.toBeNull();
    await store.remove(path);

    expect((await captureError(vault.rekey())).code).toBe('integrity');
    expect((await captureError(vault.revokeKey(await keyIdOfKey(KEY_A)))).code).toBe('integrity');
  });
});

describe('keyIdOfKey', () => {
  it('is stable and key-specific', async () => {
    expect(await keyIdOfKey(randomBytes(32))).toMatch(/^[0-9a-f]{16}$/);
    expect(await keyIdOfKey(KEY_A)).toBe(await keyIdOfKey(new Uint8Array(32).fill(1)));
    expect(await keyIdOfKey(KEY_A)).not.toBe(await keyIdOfKey(KEY_B));
  });
});
