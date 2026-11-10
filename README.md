# sovereign-vault

[![CI](https://github.com/krisakornutama/sovereign-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/krisakornutama/sovereign-vault/actions/workflows/ci.yml)

Encrypted, tamper-evident persistence for **Sovereign OS**. It stores opaque
`Uint8Array` values under logical keys, seals every object with a key derived
from a 32-byte master key, and refuses to return bytes that no longer match what
was written.

Zero runtime dependencies: AES-256-GCM, HKDF-SHA256, SHA-256 and randomness come
from WebCrypto (`globalThis.crypto`), so the core works on Node.js 20+ and in
browsers. Only the filesystem adapter (`FileBlobStore`) imports `node:fs`.

## Quick start

```ts
import { FileBlobStore, Vault, randomBytes, utf8ToBytes } from 'sovereign-vault';

const masterKey = randomBytes(32); // back this up outside the vault
const vault = await Vault.open({
  store: new FileBlobStore('./.vault-data'),
  masterKey,
});

await vault.put('note/hello', utf8ToBytes('สวัสดีจาก Sovereign Vault'));
const note = await vault.get('note/hello');
console.log(new TextDecoder().decode(note));
```

## Snapshots for the rule engine

`sovereign-rule-engine` keeps its Merkle store and CRDT register map in memory.
A snapshot is the bridge to durable, encrypted state:

```ts
import { loadSnapshot, saveSnapshot } from 'sovereign-vault';

// After a sync round or a CRDT change:
await saveSnapshot(vault, 'rule-engine/crdt', {
  version: 1,
  entries: Object.fromEntries(crdtStore.snapshot()),
});

// On boot:
const state = await loadSnapshot<{
  version: number;
  entries: Record<string, unknown>;
}>(vault, 'rule-engine/crdt');
```

The snapshot is versioned and checksummed, so a truncated or edited file is
rejected before it can be replayed into the engine. The payload is plain data,
so the engine keeps its own serialization contract.

## Rollback detection (M2)

Integrity checks catch edited, truncated or swapped blobs, but an older copy of
the whole store still authenticates perfectly. Two independent witnesses close
that gap:

```ts
import { BlobAnchorLog, FileBlobStore } from 'sovereign-vault';

// 1. Append the current root to a log kept somewhere else (second disk, synced
//    folder, remote witness). Entries are hash-chained and append-only.
const anchors = new BlobAnchorLog(new FileBlobStore('./.vault-anchors'));
await vault.anchorNow(anchors); // after a sync round, nightly, or on shutdown

// 2. On boot, fail closed if the store went backwards.
await vault.verifyAnchor(anchors); // throws VaultRollbackError on mismatch

// Or pin the root you last saw outside the vault (OS keychain, config sync):
const pinned = await Vault.open({ store, masterKey, expectedRoot: lastRoot });
```

`vault.root()` hashes the canonical index, so it changes exactly when contents
change and never because of a fresh nonce. The chain makes edits, deletions and
reordering inside the anchor log detectable; a pinned root makes a wholesale
rewrite — including rewriting the anchor log itself — detectable. Without either
one the vault cannot tell a restored backup from a wiped store, so pick a
checkpoint cadence and keep the pin outside the vault.

### Automatic checkpoints (nightly)

`checkpointAnchor` is the timer-free helper a scheduler should call. Run it as
often as you like: it appends only when the root changed or the head went stale,
so a missed or duplicated nightly run cannot fork the chain.

```ts
import { checkpointAnchor } from 'sovereign-vault';

// e.g. Task Scheduler / cron: 20:30 every night
const { appended, root } = await checkpointAnchor(vault, anchors, {
  maxAgeMs: 20 * 60 * 60 * 1000, // default: 20h
});
if (appended) console.log(`anchored ${root}`);
```

- Same root + fresh head → no-op (`appended: false`), so repeated runs are safe.
- Root changed → appends immediately, whatever the age.
- Head older than `maxAgeMs` → appends even when nothing changed, which proves
  the vault is still being witnessed.
- A nonsensical `maxAgeMs` (negative / `NaN`) throws `RangeError` instead of
  quietly writing an anchor.

## Streaming large values

`putStream`/`getStream` seal and verify one chunk at a time (default 1 MiB), so a
file larger than memory never has to be materialised:

```ts
import { createReadStream } from 'node:fs';

await vault.putStream('backup/dump.tar', createReadStream('/srv/dump.tar'), {
  chunkSize: 1024 * 1024,
});

for await (const chunk of vault.getStream('backup/dump.tar')) {
  await sink.write(chunk); // each chunk is authenticated before it is handed out
}
```

- Each chunk is sealed with its own salt/nonce and addressed by its SHA-256, so a
  tampered chunk fails before later chunks are read.
- `entry.chunks` lists `{ hash, size }` per chunk; the entry hash is SHA-256 over
  the concatenated chunk hashes (plaintext digest for single-blob `put`).
- Chunks are written before the index, so a crash leaves orphan blobs, never a
  half-readable entry; overwriting or deleting removes the old chunk blobs.
- `get()` still works on chunked entries by concatenating them — use
  `getStream()` when the value may not fit in memory.
- `rekey()` re-seals every chunk; `revokeKey()` scans them too.

## Keyring: rotation and revocation (M3)

A vault opened with `masterKey` has a one-key ring. To rotate without downtime,
open with a keyring instead: new writes use the active key, old objects stay
readable through the key that sealed them, and nothing is re-encrypted until you
ask for it.

```ts
import { Keyring, Vault } from 'sovereign-vault';

const keyring = await Keyring.create([{ key: currentKey, active: true }, { key: previousKey }]);
const vault = await Vault.open({ store, keyring });

const newId = await vault.rotateKey(freshKey); // new writes use freshKey
await vault.rekey(); // re-seal every object under freshKey
const dropped = await vault.revokeKey(oldId); // now safe; refuses while still in use
```

- `rotateKey(key)` adds a key and makes it active; reads keep working for every
  key in the ring. The index is re-sealed under the new active key.
- `rekey()` re-seals all objects (and the index) under the active key. Plaintext
  is unchanged, so **the vault root does not change** and existing anchors stay
  valid.
- `revokeKey(id)` returns `false` for an unknown id, refuses the active key, and
  refuses any key that still seals an object — so revocation can never quietly
  destroy readable data. Run `rekey()` first.
- `keyIds()` lists keys with the active one first; `activeKeyId()` tells you
  which key new writes use.
- Sharing keys between devices is still the caller's job (password manager,
  printed recovery sheet, `sovereign-attest`). The vault never exports key bytes.

## Envelope format (v1)

```
magic "SVLT" | version u8 | alg u8 | reserved u16 |
keyId 8 | salt 16 | nonce 12 | plaintext SHA-256 32 | ciphertextLength u32 |
AES-256-GCM ciphertext + 16-byte tag
```

- Object key = HKDF-SHA256(masterKey, salt = random 16 B, info = `sovereign-vault/object-key/v1`)
- AAD = header ‖ logical key name, so editing a header field or moving a blob to
  another key fails authentication
- `keyId` = first 8 bytes of SHA-256(masterKey); a wrong master key is rejected
  before any ciphertext is touched
- Every failure (truncated, tampered, swapped, missing) raises
  `VaultIntegrityError` and never returns partial data

The vault keeps an encrypted index at `index` that maps logical keys to the
plaintext hash, size and timestamp. Writes are serialized so an interleaved
`put`/`delete` cannot desync a blob from its index entry.

## API

| Member                                                   | Behaviour                                                        |
| -------------------------------------------------------- | ---------------------------------------------------------------- |
| `Vault.open({ store, masterKey                           | keyring, clock?, expectedRoot? })`                               | Validates keys, authenticates the index, enforces the pinned root |
| `put(key, bytes)`                                        | Seals and stores; returns `{ key, hash, size, updatedAt }`       |
| `get(key)`                                               | Verifies authentication and the index hash before returning      |
| `has(key)` / `list()`                                    | Index lookups, no I/O                                            |
| `delete(key)`                                            | Removes blob and index entry; `false` if absent                  |
| `verifyAll()`                                            | Re-opens every object and reports failures instead of throwing   |
| `root()`                                                 | Hex hash of the canonical index                                  |
| `anchorNow(log)` / `verifyAnchor(log)`                   | Appends a checkpoint / fails when the store is older than it     |
| `checkpointAnchor(vault, log, { maxAgeMs?, now? })`      | Idempotent nightly checkpoint: writes only when changed or stale |
| `saveSnapshot` / `loadSnapshot`                          | Versioned, checksummed state for the rule engine                 |
| `MemoryAnchorLog` / `BlobAnchorLog`                      | Hash-chained append-only roots, in memory or on any `BlobStore`  |
| `Keyring.create([{ key, active? }])` / `keyIdOfKey(key)` | Multi-key ring for rotation; key id derived from the key         |
| `rotateKey(key)` / `rekey()` / `revokeKey(id)`           | New active key / re-seal all objects / drop an unused key        |

`MemoryBlobStore` is for tests and ephemeral processes; `FileBlobStore` writes to
a temporary file and renames it into place so a crash cannot truncate an object.

## Limitations (M4)

- **Rollback needs a witness.** `anchorNow`/`verifyAnchor` and `expectedRoot`
  detect a store that went backwards, but only when the anchor log or the pin
  lives where the vault attacker cannot rewrite it. Anchoring is an explicit
  checkpoint, not part of every write, so bytes written after the last
  checkpoint are protected by integrity only.
- One device, one master key. Multi-device group keys, rotation and revocation
  come with `sovereign-attest` and the group-key milestone.
- Key names are not encrypted (they appear only in AAD, never on disk as plain
  text, but they are the map key in the encrypted index).
- No compression, deduplication or garbage collection yet. Chunked writes leave
  orphan blobs when a write crashes before the index commits; nothing sweeps them
  yet.
- Chunk boundaries are not content-defined, so inserting bytes near the start
  rewrites every following chunk (no delta sync yet).
- `checkpointAnchor` does not schedule itself and takes no cross-process lock:
  two concurrent nightly runs can append two entries (both valid, sequence just
  advances). Keep a single scheduler per anchor log.

## Commands

```bash
npm install
npm run typecheck
npm test
npm run test:coverage   # gate: 90% lines/statements/functions, 80% branches
npm run example
npm run build           # dist/ with .d.ts for downstream packages
```

## Roadmap link

This package is milestone M1/M2 of the Sovereign OS roadmap
(`sovereign-origin/docs/ROADMAP_2036.md`). Work items and their status live in
`sovereign-origin/docs/LIVING-QUEUE.md`, which is append-only: entries are never
deleted, only closed and superseded.
