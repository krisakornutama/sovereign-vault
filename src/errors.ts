export type VaultErrorCode =
  | 'invalid-key'
  | 'invalid-envelope'
  | 'invalid-root'
  | 'not-found'
  | 'integrity'
  | 'rollback'
  | 'corrupt-index'
  | 'corrupt-anchor'
  | 'store';

export class VaultError extends Error {
  readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'VaultError';
    this.code = code;
  }
}

/**
 * Thrown when the store contains an older but internally consistent state.
 * Rollback is invisible to plain integrity checks because every surviving blob
 * still authenticates; only an anchor or a pinned root can reveal it.
 */
export class VaultRollbackError extends VaultError {
  constructor(message: string, options?: ErrorOptions) {
    super('rollback', message, options);
    this.name = 'VaultRollbackError';
  }
}

/** Thrown when stored bytes no longer match what was written. */
export class VaultIntegrityError extends VaultError {
  constructor(message: string, options?: ErrorOptions) {
    super('integrity', message, options);
    this.name = 'VaultIntegrityError';
  }
}
