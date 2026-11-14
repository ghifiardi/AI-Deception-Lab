/**
 * Verify a Deception Lab audit log.
 *
 *   npm run deception-lab:verify -- <file.json> [--replay] [--pin SHA256:<fingerprint>]
 *
 * Accepts a run export from the UI ("Export run") or an experiment/agent log.
 * Checks, using node:crypto and its own canonical-JSON code (it does not reuse
 * the engine's SHA-256 implementation):
 *   1. every record's prevHash links to the previous record's hash,
 *   2. every hash equals SHA-256(canonical JSON of the record without `hash`),
 *   3. seq numbers are contiguous from 1.
 * With --replay (run exports only) it also recompiles the run from its recorded
 * inputs (scenario, mode, seed, policy, analyst decisions) and requires a
 * byte-identical log.
 *
 * Limitation: the records are not signed. A valid chain proves internal
 * consistency, not who wrote it. Compare the chain head against a copy held
 * somewhere the writer cannot modify.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

interface ChainRecord {
  seq: number;
  prevHash: string;
  hash: string;
  [k: string]: unknown;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
    .join(',')}}`;
}

export interface VerifyReport {
  ok: boolean;
  records: number;
  head: string | null;
  problems: string[];
}

export function verifyRecords(records: ChainRecord[]): VerifyReport {
  const problems: string[] = [];
  let prev = '0'.repeat(64);
  records.forEach((r, i) => {
    if (r.seq !== i + 1) problems.push(`record ${i}: seq ${r.seq}, expected ${i + 1}`);
    if (r.prevHash !== prev) problems.push(`seq ${r.seq}: prevHash does not link to previous record`);
    const { hash, ...body } = r;
    const expect = createHash('sha256').update(canonical(body), 'utf8').digest('hex');
    if (hash !== expect) problems.push(`seq ${r.seq}: hash mismatch (content altered)`);
    prev = hash;
  });
  return { ok: problems.length === 0, records: records.length, head: records.at(-1)?.hash ?? null, problems };
}

async function main() {
  const args = process.argv.slice(2);
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) {
    console.error('usage: verify-log <file.json> [--replay]');
    process.exit(2);
  }
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  if (doc.format === 'gatra-deception-lab/experiment@1' || doc.format === 'gatra-deception-lab/experiment@2') {
    let bad = 0;
    for (const run of doc.runs ?? []) {
      const rep = verifyRecords(run.log ?? []);
      const headOk = rep.head === run.logHead;
      if (!rep.ok || !headOk) bad++;
      console.log(`${rep.ok && headOk ? 'VALID  ' : 'INVALID'} trial ${run.trial} ${run.mode}: ${rep.records} records, head ${rep.head}${headOk ? '' : ' (does not match recorded logHead)'}`);
      for (const p of rep.problems.slice(0, 5)) console.log(`    - ${p}`);
    }
    console.log(`${bad === 0 ? 'ALL VALID' : `${bad} INVALID`}: ${doc.runs?.length ?? 0} run logs in experiment "${doc.label}"`);
    let sigOk = true;
    if (doc.signing) {
      const { verifySignatures } = await import('../experiments/provenance.mjs');
      const pinIdx = args.indexOf('--pin');
      const sig = verifySignatures(doc, { pinnedFingerprint: pinIdx > -1 ? args[pinIdx + 1] : undefined });
      sigOk = sig.ok;
      console.log(
        sig.ok
          ? `SIGNED: Ed25519 final signature and ${sig.checkpoints} run checkpoints valid; key ${sig.fingerprint}${pinIdx > -1 ? ' (pinned)' : ' (not pinned: compare this fingerprint with a trusted copy)'}`
          : `SIGNATURE INVALID: ${sig.reason}`,
      );
    } else {
      console.log('UNSIGNED: no signature block (chain integrity only).');
    }
    process.exit(bad === 0 && sigOk ? 0 : 1);
  }
  const records: ChainRecord[] = doc.events ?? doc.records ?? (Array.isArray(doc) ? doc : []);
  if (!records.length) {
    console.error('No chained records found (expected `events` or `records`).');
    process.exit(2);
  }
  if (doc.hashAlgorithm && doc.hashAlgorithm !== 'sha256') {
    console.error(`Unsupported hash algorithm ${doc.hashAlgorithm}`);
    process.exit(2);
  }
  const report = verifyRecords(records);
  console.log(`${report.ok ? 'VALID' : 'INVALID'}: ${report.records} records, chain head ${report.head}`);
  for (const p of report.problems.slice(0, 20)) console.log(`  - ${p}`);

  let replayOk = true;
  if (args.includes('--replay')) {
    if (doc.format !== 'gatra-deception-lab/run-export@1') {
      console.log('Replay: skipped (only run exports can be replayed).');
    } else {
      const { compileRun } = await import('../src/engine/simulator.ts');
      const rerun = compileRun({ scenario: doc.scenario, mode: doc.mode, seed: doc.seed, policy: doc.policy, analyst: doc.analyst });
      replayOk = canonical(rerun.events) === canonical(records);
      console.log(
        replayOk
          ? `Replay: IDENTICAL (${rerun.events.length} events regenerated from recorded inputs)`
          : `Replay: DIFFERENT (regenerated head ${rerun.events.at(-1)?.hash})`,
      );
    }
  }
  console.log('Note: records are unsigned; a valid chain shows internal consistency, not authorship.');
  process.exit(report.ok && replayOk ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('verify-log.ts')) await main();
