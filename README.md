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

| Member                                                    | Behaviour                                                            |
| --------------------------------------------------------- | -------------------------------------------------------------------- |
| `Vault.open({ store, masterKey, clock?, expectedRoot? })` | Validates the key, authenticates the index, enforces the pinned root |
| `put(key, bytes)`                                         | Seals and stores; returns `{ key, hash, size, updatedAt }`           |
| `get(key)`                                                | Verifies authentication and the index hash before returning          |
| `has(key)` / `list()`                                     | Index lookups, no I/O                                                |
| `delete(key)`                                             | Removes blob and index entry; `false` if absent                      |
| `verifyAll()`                                             | Re-opens every object and reports failures instead of throwing       |
| `root()`                                                  | Hex hash of the canonical index                                      |
| `anchorNow(log)` / `verifyAnchor(log)`                    | Appends a checkpoint / fails when the store is older than it         |
| `saveSnapshot` / `loadSnapshot`                           | Versioned, checksummed state for the rule engine                     |
| `MemoryAnchorLog` / `BlobAnchorLog`                       | Hash-chained append-only roots, in memory or on any `BlobStore`      |

`MemoryBlobStore` is for tests and ephemeral processes; `FileBlobStore` writes to
a temporary file and renames it into place so a crash cannot truncate an object.

## Limitations (M2)

- **Rollback needs a witness.** `anchorNow`/`verifyAnchor` and `expectedRoot`
  detect a store that went backwards, but only when the anchor log or the pin
  lives where the vault attacker cannot rewrite it. Anchoring is an explicit
  checkpoint, not part of every write, so bytes written after the last
  checkpoint are protected by integrity only.
- One device, one master key. Multi-device group keys, rotation and revocation
  come with `sovereign-attest` and the group-key milestone.
- Key names are not encrypted (they appear only in AAD, never on disk as plain
  text, but they are the map key in the encrypted index).
- No compression, deduplication or garbage collection yet.

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
