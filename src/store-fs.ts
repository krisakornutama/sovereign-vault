import { mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes, toHex } from './bytes.js';
import { VaultError } from './errors.js';
import type { BlobStore } from './store.js';

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'ENOENT'
  );
}

/**
 * Filesystem-backed store. Writes go to a temporary file and are renamed into
 * place, so a crash never leaves a half-written object under its final path.
 */
export class FileBlobStore implements BlobStore {
  private readonly root: string;

  constructor(root: string) {
    this.root = root;
  }

  async read(path: string): Promise<Uint8Array | null> {
    try {
      const bytes = await readFile(this.resolve(path));
      return new Uint8Array(bytes);
    } catch (error) {
      if (isMissingFile(error)) return null;
      throw new VaultError('store', `cannot read ${path}`, { cause: error });
    }
  }

  async write(path: string, bytes: Uint8Array): Promise<void> {
    const target = this.resolve(path);
    const temp = `${target}.tmp-${toHex(randomBytes(6))}`;
    try {
      await mkdir(dirname(target), { recursive: true });
      await writeFile(temp, bytes);
      await rename(temp, target);
    } catch (error) {
      await rm(temp, { force: true }).catch(() => undefined);
      throw new VaultError('store', `cannot write ${path}`, { cause: error });
    }
  }

  async remove(path: string): Promise<void> {
    try {
      await rm(this.resolve(path), { force: true });
    } catch (error) {
      throw new VaultError('store', `cannot remove ${path}`, { cause: error });
    }
  }

  async list(prefix: string): Promise<string[]> {
    try {
      await mkdir(this.root, { recursive: true });
    } catch (error) {
      throw new VaultError('store', `cannot open ${this.root}`, { cause: error });
    }
    const paths: string[] = [];
    await this.walk(this.root, '', paths);
    return paths.filter((path) => path.startsWith(prefix)).sort();
  }

  private resolve(path: string): string {
    const segments = path.split('/');
    if (segments.length === 0 || segments.some((segment) => segment === '..' || segment === '.')) {
      throw new VaultError('store', `invalid store path ${path}`);
    }
    if (segments.some((segment) => segment.length === 0)) {
      throw new VaultError('store', `invalid store path ${path}`);
    }
    return join(this.root, ...segments);
  }

  private async walk(directory: string, base: string, out: string[]): Promise<void> {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (isMissingFile(error)) return;
      throw new VaultError('store', `cannot list ${directory}`, {
        cause: error,
      });
    }
    for (const entry of entries) {
      const relative = base.length === 0 ? entry.name : `${base}/${entry.name}`;
      if (entry.isDirectory()) {
        await this.walk(join(directory, entry.name), relative, out);
      } else if (entry.isFile()) {
        out.push(relative);
      }
    }
  }
}
