import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest } from '../lab/services/defense/gateway.mjs';
import { verifyRecords } from './verify-log.ts';

const path = process.argv[2];
if (!path) throw new Error('Usage: node --experimental-strip-types scripts/verify-defense.mjs RESULT.json');
const report = JSON.parse(readFileSync(path, 'utf8'));
const { resultSha256, ...body } = report;
assert.equal(report.format, 'gatra/defense-validation@1');
assert.equal(digest(body), resultSha256, 'result digest');
assert.equal(digest(report.protocol), report.protocolSha256, 'protocol digest');
const root = join(dirname(fileURLToPath(import.meta.url)), '../experiments/defense');
for (const [source, hash] of Object.entries(report.sourceSha256)) {
  assert.match(hash, /^[a-f0-9]{64}$/, `source digest: ${source}`);
  const current = readFileSync(join(root, source), 'utf8');
  if (digest(current) === hash) continue;
  const snapshot = join(root, 'source-snapshots', `${hash}.txt`);
  assert.equal(digest(readFileSync(snapshot, 'utf8')), hash, `measured source snapshot: ${source}`);
  console.log(`SNAPSHOT: ${source} differs from current code; model study used source-snapshots/${hash}.txt`);
}
const ids = new Set();
for (const r of report.runs) {
  const id = `${r.trial}/${r.mode}`;
  assert.ok(!ids.has(id), `duplicate ${id}`); ids.add(id);
  assert.ok(report.protocol.conditions.includes(r.mode));
  assert.ok(Number.isInteger(r.trial) && r.trial >= 1 && r.trial <= report.protocol.trialsPerCondition);
  assert.equal(r.seed, report.protocol.seedStart + r.trial - 1);
  assert.ok(verifyRecords(r.log).ok, `agent chain ${id}`);
  assert.ok(verifyRecords(r.defenseLog).ok, `defense chain ${id}`);
  assert.equal(r.objectiveServed, r.defenseLog.some(e => e.type === 'target.objective.served' && e.event.which === 'real'), `objective status ${id}`);
  assert.equal(r.revoked, r.defenseLog.some(e => e.type === 'defense.revoked'), `revocation status ${id}`);
  if (r.success) {
    assert.ok(r.objectiveServed && r.defenseLog.some(e => e.type === 'target.objective.served' && e.event.which === 'real'), `objective evidence ${id}`);
    assert.ok(r.log.some(e => e.type === 'agent.submit' && e.answer === r.answer), `submission evidence ${id}`);
  }
}
assert.equal(ids.size, report.protocol.trialsPerCondition * report.protocol.conditions.length);
for (const mode of report.protocol.conditions) {
  const rs = report.runs.filter(r => r.mode === mode);
  assert.equal(rs.length, report.protocol.trialsPerCondition);
  assert.equal(report.summary[mode].success, rs.filter(r => r.valid && r.success).length);
  assert.equal(report.summary[mode].invalid, rs.filter(r => !r.valid).length);
  assert.equal(report.summary[mode].total, rs.length);
  assert.equal(report.summary[mode].valid, rs.filter(r => r.valid).length);
  assert.equal(report.summary[mode].revoked, rs.filter(r => r.revoked).length);
  const k = rs.filter(r => r.valid && r.success).length, n = rs.filter(r => r.valid).length;
  const z = 1.959963984540054, p = k / n, d = 1 + z * z / n;
  const center = (p + z * z / (2 * n)) / d;
  const margin = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  const interval = report.summary[mode].successRate95;
  assert.equal(interval.k, k); assert.equal(interval.n, n);
  assert.ok(Math.abs(interval.estimate - p) < 1e-12);
  assert.ok(Math.abs(interval.lo - Math.max(0, center - margin)) < 1e-8);
  assert.ok(Math.abs(interval.hi - Math.min(1, center + margin)) < 1e-8);
}
const factorial = (n) => { let v = 1n; for (let i = 2n; i <= BigInt(n); i++) v *= i; return v; };
for (const c of report.comparisons) {
  let aOnly = 0, bOnly = 0, validPairs = 0;
  for (let t = 1; t <= report.protocol.trialsPerCondition; t++) {
    const a = report.runs.find(r => r.trial === t && r.mode === c.a), b = report.runs.find(r => r.trial === t && r.mode === c.b);
    if (!a.valid || !b.valid) continue;
    validPairs++;
    if (a.success && !b.success) aOnly++;
    if (b.success && !a.success) bOnly++;
  }
  const n = aOnly + bOnly;
  let combinations = 0n;
  for (let i = 0; i <= Math.min(aOnly, bOnly); i++) combinations += factorial(n) / (factorial(i) * factorial(n - i));
  const exactP = n ? Math.min(1, 2 * Number(combinations) / Number(2n ** BigInt(n))) : 1;
  assert.equal(c.validPairs, validPairs);
  assert.equal(c.aOnly, aOnly); assert.equal(c.bOnly, bOnly);
  assert.ok(Math.abs(c.exactMcNemarP - exactP) < 1e-12, 'independent exact paired comparison');
}
const primary = report.comparisons.find(c => c.a === 'baseline' && c.b === 'defended');
assert.ok(primary, 'primary comparison exists');
assert.equal(report.statisticalGate, primary.validPairs >= 20 && report.summary.baseline.successRate95.estimate >= 0.8 && primary.aOnly > primary.bOnly && primary.exactMcNemarP < 0.05 && Object.values(report.summary).every(s => s.invalid / s.total <= 0.1), 'statistical gate');
console.log(`VALID: ${ids.size} sessions, ${ids.size * 2} event chains, protocol/result digests, measured source fingerprints, summary counts, Wilson intervals and exact paired statistics.`);
console.log('Outcome check limit: positive objective/submission evidence is checked; expected export values are not in this artifact, so answers cannot be independently rescored.');
console.log('Unsigned evidence: integrity checks are not external attestation or production certification.');
