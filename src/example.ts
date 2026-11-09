import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FileBlobStore,
  Vault,
  bytesToUtf8,
  randomBytes,
  saveSnapshot,
  loadSnapshot,
  utf8ToBytes,
} from './index.js';

const directory = await mkdtemp(join(tmpdir(), 'sovereign-vault-'));
const masterKey = randomBytes(32);

try {
  const store = new FileBlobStore(directory);
  const vault = await Vault.open({ store, masterKey });

  await vault.put('note/hello', utf8ToBytes('สวัสดีจาก Sovereign Vault'));
  await saveSnapshot(vault, 'rule-engine/crdt', {
    version: 1,
    entries: { 'config:theme': { value: 'dark', updatedAt: 10 } },
  });

  const reopened = await Vault.open({ store, masterKey });
  const note = await reopened.get('note/hello');
  const snapshot = await loadSnapshot<{ version: number }>(reopened, 'rule-engine/crdt');
  const report = await reopened.verifyAll();

  console.log(
    'entries:',
    reopened
      .list()
      .map((entry) => entry.key)
      .join(', ')
  );
  console.log('note:', bytesToUtf8(note));
  console.log('snapshot version:', snapshot?.version);
  console.log('verify:', report.checked, 'checked,', report.failures.length, 'failures');
} finally {
  await rm(directory, { recursive: true, force: true });
}
