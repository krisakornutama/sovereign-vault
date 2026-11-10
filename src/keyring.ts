import { sha256, toHex } from './bytes.js';
import { VaultError } from './errors.js';
import { KEY_ID_LENGTH, MASTER_KEY_LENGTH } from './envelope.js';

export interface VaultKeyInput {
  /** 32 random bytes. Losing every key that sealed data means losing that data. */
  readonly key: Uint8Array;
  /** Exactly one key must be active (the one new writes use). */
  readonly active?: boolean;
}

export async function keyIdOfKey(key: Uint8Array): Promise<string> {
  return toHex((await sha256(key)).slice(0, KEY_ID_LENGTH));
}

function assertKeyBytes(key: unknown): asserts key is Uint8Array {
  if (!(key instanceof Uint8Array) || key.length !== MASTER_KEY_LENGTH) {
    throw new VaultError(
      'invalid-key',
      `vault key must be a Uint8Array of ${MASTER_KEY_LENGTH} bytes`
    );
  }
}

/**
 * The set of keys a vault accepts: one active key for new writes plus any older
 * keys still needed to read what they sealed.
 *
 * This is what makes rotation and revocation possible without re-encrypting the
 * world first: rotate makes a new key active, `rekey()` re-seals objects, and
 * `revoke()` refuses to drop a key while anything still uses it.
 *
 * Sharing these keys between devices is the caller's job (password manager,
 * printed recovery sheet, `sovereign-attest`): the vault never exports them.
 */
export class Keyring {
  private readonly keys: Map<string, Uint8Array>;
  private active: string;

  private constructor(keys: Map<string, Uint8Array>, active: string) {
    this.keys = keys;
    this.active = active;
  }

  /** Builds a keyring from explicit keys; multiple keys need one marked active. */
  static async create(inputs: readonly VaultKeyInput[]): Promise<Keyring> {
    if (!Array.isArray(inputs) || inputs.length === 0) {
      throw new VaultError('invalid-key', 'keyring needs at least one key');
    }
    const keys = new Map<string, Uint8Array>();
    let active: string | undefined;
    for (const input of inputs) {
      assertKeyBytes(input?.key);
      const id = await keyIdOfKey(input.key);
      keys.set(id, new Uint8Array(input.key));
      if (input.active === true) {
        if (active !== undefined && active !== id) {
          throw new VaultError('invalid-key', 'keyring has more than one active key');
        }
        active = id;
      }
    }
    if (active === undefined) {
      if (keys.size > 1) {
        throw new VaultError(
          'invalid-key',
          'keyring with several keys must mark exactly one as active'
        );
      }
      active = [...keys.keys()][0] as string;
    }
    return new Keyring(keys, active);
  }

  get activeId(): string {
    return this.active;
  }

  get size(): number {
    return this.keys.size;
  }

  ids(): string[] {
    return [...this.keys.keys()];
  }

  has(id: string): boolean {
    return this.keys.has(id);
  }

  keyFor(id: string): Uint8Array | undefined {
    return this.keys.get(id);
  }

  /** Adds a key; `activate: true` makes it the key for new writes. */
  async add(key: Uint8Array, options: { readonly activate?: boolean } = {}): Promise<string> {
    assertKeyBytes(key);
    const id = await keyIdOfKey(key);
    if (!this.keys.has(id)) this.keys.set(id, new Uint8Array(key));
    if (options.activate === true) this.active = id;
    return id;
  }

  activate(id: string): void {
    if (!this.keys.has(id)) {
      throw new VaultError('unknown-key', `keyring has no key ${id}`);
    }
    this.active = id;
  }

  /** Removes a non-active key; the active key can never be revoked. */
  remove(id: string): boolean {
    if (id === this.active) {
      throw new VaultError('invalid-key', 'cannot revoke the active key; rotate first');
    }
    return this.keys.delete(id);
  }
}
