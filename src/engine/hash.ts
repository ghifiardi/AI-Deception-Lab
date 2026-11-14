/**
 * Tamper-evident event chain (SHA-256).
 *
 *   hash_n = SHA-256( canonicalJson(event_n without `hash`) )   where event_n.prevHash = hash_{n-1}
 *
 * Editing, removing or reordering any event breaks verification from that
 * point on. Records are NOT signed: anyone able to rewrite the whole log can
 * recompute every hash. See docs/DESIGN.md §"Integrity limitations" for what
 * a production audit trail additionally needs (signatures, external anchoring).
 *
 * The same rule is implemented independently with node:crypto in
 * scripts/verify-log.ts so verification does not trust this module.
 */
import { sha256Hex } from './sha256.ts';

export const HASH_ALGORITHM = 'sha256' as const;
export const GENESIS_HASH = '0'.repeat(64);

/** JSON with sorted keys; undefined fields are dropped so field order never changes the hash. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export interface Chained {
  seq: number;
  prevHash: string;
  hash: string;
}

export function hashRecord<T extends object>(record: T): string {
  return sha256Hex(canonicalJson(record));
}

export interface ChainCheck {
  ok: boolean;
  /** seq of the first record that fails verification, if any. */
  brokenAt?: number;
  reason?: string;
}

export function verifyChain(records: readonly Chained[]): ChainCheck {
  let prev = GENESIS_HASH;
  for (const r of records) {
    const { hash, ...rest } = r;
    if (r.prevHash !== prev) return { ok: false, brokenAt: r.seq, reason: 'prevHash does not match previous record' };
    if (hashRecord(rest) !== hash) return { ok: false, brokenAt: r.seq, reason: 'hash does not match record content' };
    prev = hash;
  }
  return { ok: true };
}
