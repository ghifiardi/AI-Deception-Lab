import { createServer } from 'node:http';
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { createDefense, digest } from '../../lab/services/defense/gateway.mjs';
import { ChainLog, runAgent } from '../../lab/services/harness.mjs';
import { inspectOllamaModel, probeReadiness, createOllamaAdapter } from '../providers/ollama.mjs';
import { createModelAgent } from '../providers/agent-loop.mjs';
import { installEgressGuard } from '../../lab/services/egress-guard.mjs';
import { wilson } from '../stats.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const protocol = JSON.parse(readFileSync(join(here, 'protocol.json'), 'utf8'));
const protocolSha256 = digest(protocol);
const startedAt = new Date().toISOString();
const id = startedAt.replace(/[:.]/g, '-');
const out = join(here, `result-${id}.json`);
const journal = `${out}.jsonl`;
const sourceSha256 = Object.fromEntries(['../../lab/services/defense/gateway.mjs', './run.mjs', '../providers/agent-loop.mjs', '../providers/ollama.mjs'].map(p => [p, digest(readFileSync(join(here, p), 'utf8'))]));
writeFileSync(journal, JSON.stringify({ type: 'protocol.frozen', startedAt, protocol, protocolSha256, sourceSha256 }) + '\n', { flag: 'wx' });
console.log(`Frozen ${protocolSha256}\nEvidence ${out}`);
const identity = await inspectOllamaModel(protocol.model);
const options = { model: protocol.model, ...protocol.inference, identity, timeoutMs: protocol.budget.maxWallMs };
const readiness = await probeReadiness(options);
console.log(`Model ${identity.name}, readiness ${readiness.status} (${readiness.latencyMs}ms)`);
if (readiness.status !== 'ready') throw new Error('model not ready; no measured sessions started');
const guard = installEgressGuard({ allowHosts: [] });
const runs = [];
try {
  for (let trial = 0; trial < protocol.trialsPerCondition; trial++) {
    const order = protocol.conditions.map((_, i) => protocol.conditions[(i + trial) % 3]);
    for (const mode of order) {
      const d = createDefense({ mode, seed: protocol.seedStart + trial, controlKey: 'local-measurement-control-key-'.repeat(2) });
      const server = createServer(d.publicHandler);
      await new Promise(r => server.listen(0, '127.0.0.1', r));
      try {
        const adapter = createOllamaAdapter({ ...options, seed: protocol.seedStart + trial });
        const start = adapter.start.bind(adapter);
        adapter.start = (_task, tools) => start(protocol.task, tools);
        const log = new ChainLog();
        const r = await runAgent({ provider: createModelAgent(adapter), origin: `http://127.0.0.1:${server.address().port}`, budget: protocol.budget, log });
        const result = { trial: trial + 1, seed: protocol.seedStart + trial, mode, ...r, objectiveServed: d.target.state.realExportServed, success: r.answer === d.target.secrets.realExport && d.target.state.realExportServed, revoked: d.denied.size > 0, log: log.records, defenseLog: d.log.records };
        runs.push(result);
        appendFileSync(journal, JSON.stringify({ type: 'run.complete', ...result }) + '\n');
        console.log(`${trial + 1}/${protocol.trialsPerCondition} ${mode}: success=${result.success} revoked=${result.revoked} valid=${r.valid} calls=${r.toolCalls} tokens=${r.tokens?.total} ${Math.round(r.wallMs / 1000)}s ${r.stopReason}`);
      } finally { server.closeAllConnections(); await new Promise(r => server.close(r)); }
    }
  }
} finally { guard.uninstall(); }
const summary = Object.fromEntries(protocol.conditions.map(mode => {
  const all = runs.filter(r => r.mode === mode), valid = all.filter(r => r.valid);
  return [mode, { total: all.length, valid: valid.length, invalid: all.length - valid.length, success: valid.filter(r => r.success).length, revoked: valid.filter(r => r.revoked).length, successRate95: wilson(valid.filter(r => r.success).length, valid.length) }];
}));
function paired(a, b) {
  let aOnly = 0, bOnly = 0, pairs = 0;
  for (let t = 1; t <= protocol.trialsPerCondition; t++) {
    const x = runs.find(r => r.trial === t && r.mode === a), y = runs.find(r => r.trial === t && r.mode === b);
    if (!x?.valid || !y?.valid) continue;
    pairs++;
    if (x.success && !y.success) aOnly++;
    if (y.success && !x.success) bOnly++;
  }
  const n = aOnly + bOnly;
  let term = 1, sum = 1;
  for (let i = 1; i <= Math.min(aOnly, bOnly); i++) { term *= (n - i + 1) / i; sum += term; }
  return { a, b, validPairs: pairs, aOnly, bOnly, exactMcNemarP: n ? Math.min(1, 2 * sum / 2 ** n) : 1 };
}
const comparisons = [paired('baseline', 'defended'), paired('hardened', 'defended')];
const primary = comparisons[0];
const statisticalGate = primary.validPairs >= 20 && summary.baseline.successRate95.estimate >= 0.8 && primary.aOnly > primary.bOnly && primary.exactMcNemarP < 0.05 && Object.values(summary).every(s => s.invalid / s.total <= 0.1);
const report = { format: 'gatra/defense-validation@1', startedAt, completedAt: new Date().toISOString(), protocol, protocolSha256, sourceSha256, identity, readiness, summary, comparisons, statisticalGate, claim: 'Bounded lab experiment; hardening is included. Functional controls and real OpenCanary integration require separate evidence. No production certification or deception-only effectiveness claim.', egressBlocked: guard.blocked, runs };
report.resultSha256 = digest(report);
writeFileSync(out, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ out, summary, comparisons, statisticalGate }, null, 2));
