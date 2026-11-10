import type { AnchorEntry, AnchorLog } from './anchor.js';
import type { Vault } from './vault.js';

/**
 * How old the newest anchor may be before a checkpoint is due.
 * 20h leaves room for a nightly run that slips (machine asleep, task late)
 * without writing a second anchor in the same night.
 */
export const DEFAULT_ANCHOR_MAX_AGE_MS = 20 * 60 * 60 * 1000;

export interface AnchorCheckpointOptions {
  /** Append when the head is older than this. Default 20h. */
  readonly maxAgeMs?: number;
  /** Injectable clock (tests, monotonic sources). Default `Date.now`. */
  readonly now?: () => number;
}

export interface AnchorCheckpointResult {
  /** `true` when this call wrote an entry. */
  readonly appended: boolean;
  /** Vault root observed by this run. */
  readonly root: string;
  /** Entry written this run, or `null` when the anchor was already fresh. */
  readonly entry: AnchorEntry | null;
}

/**
 * Idempotent checkpoint for schedulers (cron / Task Scheduler / a nightly job):
 * safe to call as often as you like, it only writes when something changed or
 * the head went stale. Kept timer-free so a caller owns its own scheduling and
 * an embedder never gets a background loop it did not ask for.
 */
export async function checkpointAnchor(
  vault: Vault,
  log: AnchorLog,
  options: AnchorCheckpointOptions = {}
): Promise<AnchorCheckpointResult> {
  const maxAgeMs = options.maxAgeMs ?? DEFAULT_ANCHOR_MAX_AGE_MS;
  if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) {
    throw new RangeError('maxAgeMs must be a finite, non-negative number');
  }
  const now = options.now ?? Date.now;

  const entries = await log.entries();
  const last = entries.at(-1);
  const root = await vault.root();
  if (last !== undefined && last.root === root && now() - last.at < maxAgeMs) {
    return { appended: false, root, entry: null };
  }

  const entry = await vault.anchorNow(log, now());
  return { appended: true, root, entry };
}
