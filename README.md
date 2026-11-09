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

| Member                                     | Behaviour                                                      |
| ------------------------------------------ | -------------------------------------------------------------- |
| `Vault.open({ store, masterKey, clock? })` | Validates the key, loads and authenticates the index           |
| `put(key, bytes)`                          | Seals and stores; returns `{ key, hash, size, updatedAt }`     |
| `get(key)`                                 | Verifies authentication and the index hash before returning    |
| `has(key)` / `list()`                      | Index lookups, no I/O                                          |
| `delete(key)`                              | Removes blob and index entry; `false` if absent                |
| `verifyAll()`                              | Re-opens every object and reports failures instead of throwing |
| `saveSnapshot` / `loadSnapshot`            | Versioned, checksummed state for the rule engine               |

`MemoryBlobStore` is for tests and ephemeral processes; `FileBlobStore` writes to
a temporary file and renames it into place so a crash cannot truncate an object.

## Limitations (M1)

- **Rollback is not detected yet.** An attacker with write access to the whole
  store can restore an older, internally consistent snapshot. The next milestone
  anchors the index root in an append-only log / external witness.
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
```
