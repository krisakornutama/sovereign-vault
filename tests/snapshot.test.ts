import { describe, expect, it } from 'vitest';
import {
  MemoryBlobStore,
  Vault,
  VaultIntegrityError,
  decodeSnapshot,
  encodeSnapshot,
  loadSnapshot,
  randomBytes,
  saveSnapshot,
  utf8ToBytes,
} from '../src/index.js';

const MASTER_KEY = randomBytes(32);

async function openVault(): Promise<Vault> {
  return Vault.open({ store: new MemoryBlobStore(), masterKey: MASTER_KEY });
}

describe('snapshot encoding', () => {
  it('round-trips JSON state', async () => {
    const state = {
      version: 1,
      entries: { 'config:theme': { value: 'dark', updatedAt: 10 } },
      peers: ['peer-a', 'peer-b'],
    };
    const decoded = await decodeSnapshot<typeof state>(await encodeSnapshot(state));
    expect(decoded).toEqual(state);
  });

  it('round-trips primitives and null', async () => {
    for (const value of [42, 'text', true, null, [1, 2, 3]]) {
      expect(await decodeSnapshot(await encodeSnapshot(value))).toEqual(value);
    }
  });

  it('refuses data that cannot be serialized', async () => {
    await expect(encodeSnapshot(undefined)).rejects.toMatchObject({
      code: 'invalid-key',
    });
    await expect(encodeSnapshot(() => undefined)).rejects.toMatchObject({
      code: 'invalid-key',
    });
  });

  it('rejects invalid JSON and malformed headers', async () => {
    await expect(decodeSnapshot(utf8ToBytes('not json'))).rejects.toMatchObject({
      code: 'invalid-envelope',
    });

    const malformed = [
      '[]',
      '{"version":2,"checksum":"00","data":null}',
      '{"version":1,"data":null}',
      '{"version":1,"checksum":7,"data":null}',
      '{"version":1,"checksum":"00"}',
    ];
    for (const payload of malformed) {
      await expect(decodeSnapshot(utf8ToBytes(payload))).rejects.toMatchObject({
        code: 'invalid-envelope',
      });
    }
  });

  it('rejects data that no longer matches its checksum', async () => {
    const bytes = await encodeSnapshot({ value: 'original' });
    const tampered = new TextDecoder().decode(bytes).replace('original', 'tampered');

    const error = await decodeSnapshot(utf8ToBytes(tampered)).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(VaultIntegrityError);
  });
});

describe('snapshots in a vault', () => {
  it('saves and loads a snapshot through the encrypted vault', async () => {
    const vault = await openVault();
    const state = { entries: { a: 1 }, cursor: 7 };
    await saveSnapshot(vault, 'rule-engine/crdt', state);

    expect(vault.list().map((entry) => entry.key)).toEqual(['snapshot/rule-engine/crdt']);
    expect(await loadSnapshot(vault, 'rule-engine/crdt')).toEqual(state);
  });

  it('returns null for a snapshot that was never saved', async () => {
    const vault = await openVault();
    expect(await loadSnapshot(vault, 'missing')).toBeNull();
  });

  it('overwrites a snapshot in place', async () => {
    const vault = await openVault();
    await saveSnapshot(vault, 'rule-engine/crdt', { cursor: 1 });
    await saveSnapshot(vault, 'rule-engine/crdt', { cursor: 2 });

    expect(vault.list()).toHaveLength(1);
    expect(await loadSnapshot(vault, 'rule-engine/crdt')).toEqual({
      cursor: 2,
    });
  });
});
