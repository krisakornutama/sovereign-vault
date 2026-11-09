import { describe, expect, it } from 'vitest';
import {
  VaultError,
  VaultIntegrityError,
  openObject,
  randomBytes,
  sealObject,
  sha256,
  utf8ToBytes,
} from '../src/index.js';

const MASTER_KEY = randomBytes(32);

async function keyId(masterKey: Uint8Array = MASTER_KEY): Promise<Uint8Array> {
  return (await sha256(masterKey)).slice(0, 8);
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

describe('envelope', () => {
  it('seals and opens a value for the same key and context', async () => {
    const sealed = await sealObject(MASTER_KEY, await keyId(), 'note/hello', utf8ToBytes('secret'));
    const opened = await openObject(MASTER_KEY, await keyId(), 'note/hello', sealed);

    expect(new TextDecoder().decode(opened)).toBe('secret');
  });

  it('uses a fresh salt and nonce for every seal', async () => {
    const first = await sealObject(MASTER_KEY, await keyId(), 'k', utf8ToBytes('same'));
    const second = await sealObject(MASTER_KEY, await keyId(), 'k', utf8ToBytes('same'));

    expect(first).not.toEqual(second);
  });

  it('opens an empty value', async () => {
    const sealed = await sealObject(MASTER_KEY, await keyId(), 'empty', new Uint8Array());
    expect(await openObject(MASTER_KEY, await keyId(), 'empty', sealed)).toEqual(new Uint8Array());
  });

  it('rejects a different context', async () => {
    const sealed = await sealObject(MASTER_KEY, await keyId(), 'alpha', utf8ToBytes('secret'));
    expect(
      await captureError(openObject(MASTER_KEY, await keyId(), 'beta', sealed))
    ).toBeInstanceOf(VaultIntegrityError);
  });

  it('rejects a different master key', async () => {
    const otherKey = randomBytes(32);
    const sealed = await sealObject(MASTER_KEY, await keyId(), 'k', utf8ToBytes('secret'));
    const error = await captureError(openObject(otherKey, await keyId(otherKey), 'k', sealed));
    expect(error.code).toBe('integrity');
  });

  it('rejects a bad magic prefix', async () => {
    const sealed = await sealObject(MASTER_KEY, await keyId(), 'k', utf8ToBytes('secret'));
    sealed[0] = 0x00;
    expect(await captureError(openObject(MASTER_KEY, await keyId(), 'k', sealed))).toBeInstanceOf(
      VaultIntegrityError
    );
  });

  it('rejects unsupported versions and algorithms', async () => {
    const versionSealed = await sealObject(MASTER_KEY, await keyId(), 'k', utf8ToBytes('secret'));
    versionSealed[4] = 9;
    expect(
      (await captureError(openObject(MASTER_KEY, await keyId(), 'k', versionSealed))).code
    ).toBe('invalid-envelope');

    const algorithmSealed = await sealObject(MASTER_KEY, await keyId(), 'k', utf8ToBytes('secret'));
    algorithmSealed[5] = 9;
    expect(
      (await captureError(openObject(MASTER_KEY, await keyId(), 'k', algorithmSealed))).code
    ).toBe('invalid-envelope');
  });

  it('rejects truncated envelopes and lying lengths', async () => {
    const sealed = await sealObject(MASTER_KEY, await keyId(), 'k', utf8ToBytes('secret'));
    expect(
      await captureError(openObject(MASTER_KEY, await keyId(), 'k', sealed.slice(0, 20)))
    ).toBeInstanceOf(VaultIntegrityError);

    const lying = sealed.slice();
    lying[79] = 0x01;
    expect(await captureError(openObject(MASTER_KEY, await keyId(), 'k', lying))).toBeInstanceOf(
      VaultIntegrityError
    );
  });
});
