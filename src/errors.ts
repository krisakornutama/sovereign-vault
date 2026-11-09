export type VaultErrorCode =
  'invalid-key' | 'invalid-envelope' | 'not-found' | 'integrity' | 'corrupt-index' | 'store';

export class VaultError extends Error {
  readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'VaultError';
    this.code = code;
  }
}

/** Thrown when stored bytes no longer match what was written. */
export class VaultIntegrityError extends VaultError {
  constructor(message: string, options?: ErrorOptions) {
    super('integrity', message, options);
    this.name = 'VaultIntegrityError';
  }
}
