/**
 * Minimal storage contract the vault needs. Paths are relative, POSIX-style and
 * never leave the store root, so the same vault works on a filesystem, in
 * memory, or on top of any other durable medium.
 */
export interface BlobStore {
  read(path: string): Promise<Uint8Array | null>;
  write(path: string, bytes: Uint8Array): Promise<void>;
  remove(path: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

export class MemoryBlobStore implements BlobStore {
  private readonly blobs = new Map<string, Uint8Array>();

  async read(path: string): Promise<Uint8Array | null> {
    const bytes = this.blobs.get(path);
    return bytes ? new Uint8Array(bytes) : null;
  }

  async write(path: string, bytes: Uint8Array): Promise<void> {
    this.blobs.set(path, new Uint8Array(bytes));
  }

  async remove(path: string): Promise<void> {
    this.blobs.delete(path);
  }

  async list(prefix: string): Promise<string[]> {
    return [...this.blobs.keys()].filter((path) => path.startsWith(prefix)).sort();
  }

  get size(): number {
    return this.blobs.size;
  }
}
