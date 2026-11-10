import { describe, expect, it } from 'vitest';
import { MemoryAnchorLog, MemoryBlobStore, Vault } from '../src/index.js';
import { DEFAULT_ANCHOR_MAX_AGE_MS, checkpointAnchor } from '../src/checkpoint.js';

const HOUR = 60 * 60 * 1000;

async function makeVault(key: Uint8Array = new Uint8Array(32).fill(7)): Promise<Vault> {
  return Vault.open({ store: new MemoryBlobStore(), masterKey: key });
}

describe('checkpointAnchor', () => {
  it('writes the first anchor for an empty log', async () => {
    const vault = await makeVault();
    const log = new MemoryAnchorLog();

    const result = await checkpointAnchor(vault, log, { now: () => 1000 });

    expect(result.appended).toBe(true);
    expect(result.entry?.seq).toBe(1);
    expect(result.entry?.at).toBe(1000);
    expect(result.root).toBe(await vault.root());
    expect(await log.entries()).toHaveLength(1);
  });

  it('skips when the head already vouches for the same root and is fresh', async () => {
    const vault = await makeVault();
    const log = new MemoryAnchorLog();
    await checkpointAnchor(vault, log, { now: () => 1000 });

    const again = await checkpointAnchor(vault, log, { now: () => 1000 + HOUR });

    expect(again.appended).toBe(false);
    expect(again.entry).toBeNull();
    expect(again.root).toBe(await vault.root());
    expect(await log.entries()).toHaveLength(1);
  });

  it('appends when the head is older than maxAgeMs', async () => {
    const vault = await makeVault();
    const log = new MemoryAnchorLog();
    await checkpointAnchor(vault, log, { now: () => 0 });

    const stale = await checkpointAnchor(vault, log, {
      now: () => DEFAULT_ANCHOR_MAX_AGE_MS,
    });

    expect(stale.appended).toBe(true);
    expect(stale.entry?.seq).toBe(2);
    expect(stale.entry?.prev).toBe((await log.entries())[0]?.chain);
  });

  it('appends immediately when the vault changed', async () => {
    const vault = await makeVault();
    const log = new MemoryAnchorLog();
    await checkpointAnchor(vault, log, { now: () => 1000 });

    await vault.put('note/hello', new TextEncoder().encode('hi'));
    const afterChange = await checkpointAnchor(vault, log, { now: () => 1001 });

    expect(afterChange.appended).toBe(true);
    expect(afterChange.entry?.root).toBe(await vault.root());
    expect((await log.entries()).at(-1)?.seq).toBe(2);
  });

  it('honours a custom maxAgeMs', async () => {
    const vault = await makeVault();
    const log = new MemoryAnchorLog();
    await checkpointAnchor(vault, log, { now: () => 0 });

    const tooSoon = await checkpointAnchor(vault, log, { now: () => 500, maxAgeMs: 1000 });
    expect(tooSoon.appended).toBe(false);

    const due = await checkpointAnchor(vault, log, { now: () => 1000, maxAgeMs: 1000 });
    expect(due.appended).toBe(true);
  });

  it('rejects a nonsensical maxAgeMs instead of silently anchoring', async () => {
    const vault = await makeVault();
    const log = new MemoryAnchorLog();

    await expect(checkpointAnchor(vault, log, { maxAgeMs: -1 })).rejects.toThrow(RangeError);
    await expect(checkpointAnchor(vault, log, { maxAgeMs: Number.NaN })).rejects.toThrow(
      RangeError
    );
    expect(await log.entries()).toHaveLength(0);
  });
});
