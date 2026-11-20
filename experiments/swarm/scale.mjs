/** Local capacity check: real gateway and hub, deterministic scripted clients. */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createDefense, digest } from '../../lab/services/defense/gateway.mjs';
import { createHub } from '../../lab/services/swarm/hub.mjs';
import { main, validateScale } from './run.mjs';

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`));
});
const close = (server) => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); });
const sizes = process.argv.slice(2).length ? process.argv.slice(2).map(Number) : [100, 250, 500];
for (const agents of sizes) validateScale({ agents, concurrency: agents });
const rows = [];
for (const count of sizes) {
  const concurrency = Math.min(count, 64);
  const controlKey = randomBytes(32).toString('hex');
  const legitKey = randomBytes(32).toString('hex');
  const stackId = `local:scale:${count}:${randomBytes(4).toString('hex')}`;
  let hub;
  const defense = createDefense({ mode: 'defended', stackId, controlKey, legitimateKey: legitKey, peerHeader: 'x-lab-peer', onEvent: (event) => hub?.ingest({ source: 'defense', event }) });
  const gateway = createServer(defense.publicHandler);
  try {
    const upstream = await listen(gateway);
    hub = createHub({ upstream });
    const origin = await listen(hub.server);
    const result = await main({ provider: 'scripted', agents: count, concurrency, roles: [], target: origin, basePath: '/lab', hub: origin, controlKey, legitKey, model: '', seed: 42, budget: {}, expectMode: 'defended', expectStack: stackId });
    const { agents, summary, outPath, journalPath } = result;
    for (const agent of agents) {
      let prevHash = '0'.repeat(64);
      for (const { hash, ...record } of agent.log) {
        assert.equal(record.prevHash, prevHash);
        assert.equal(digest(record), hash);
        prevHash = hash;
        if (record.type === 'tool.http') assert.notEqual(record.status, 0, 'transport failure');
      }
      const expected = { recon: 'no-objective', harvest: 'revoked', exploit: 'revoked', bait: 'blocked', legit: 'success' };
      assert.equal(agent.outcome, expected[agent.role]);
      assert.equal(defense.denied.has(`peer:${agent.agentId}`), ['harvest', 'exploit'].includes(agent.role));
    }
    const { digest: recordedDigest, ...document } = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(digest(document), recordedDigest);
    const journal = readFileSync(journalPath, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(journal.filter((e) => e.type === 'agent.complete').length, count);
    assert.equal(agents.length, count);
    assert.equal(new Set(agents.map((a) => a.agentId)).size, count);
    assert.equal(summary.scale.peakActive, concurrency);
    assert.equal(summary.validity.defendedRun, true);
    rows.push({ count, concurrency, ...summary.scale, revoked: summary.revokedAgents, legitimateSuccesses: summary.byKind.legit.success, result: outPath, journal: journalPath, digest: recordedDigest });
    assert.equal(journal.at(-1).type, 'engagement.completed');
    assert.equal(hub.state().engagement.status, 'completed');

  } finally {
    if (hub) await close(hub.server);
    await close(gateway);
  }
}
mkdirSync('docs/evidence', { recursive: true });
const note = `docs/evidence/${new Date().toISOString().replace(/[:.]/g, '-')}-swarm-scale.md`;
writeFileSync(note, [
  '# Local scripted swarm capacity test', '',
  'Real loopback Defense V2 gateway and hub; scripted agents with independent signed peer identities. No model inference, Docker, GCP, IAP, or OpenCanary container was tested. Agents run independent role plans; no shared agent memory or coordination protocol is implemented.', '',
  'Assertions passed: expected outcome for every role, exact per-peer revocation, legitimate exports, attested defended stack, all agent log chains, result digests, complete journals, and peak active harness count. Peak active means overlapping agent sessions, not simultaneous model inference.', '',
  '| Agents / concurrency | Elapsed seconds | Agents/second | Revoked | Legitimate successes | Dropped telemetry |',
  '| --- | --- | --- | --- | --- | --- |',
  ...rows.map((r) => `| ${r.count} / ${r.concurrency} | ${(r.elapsedMs / 1000).toFixed(2)} | ${r.completedAgentsPerSecond.toFixed(1)} | ${r.revoked} | ${r.legitimateSuccesses} | ${r.telemetryDropped} |`), '',
  'The initial 250-concurrency burst produced ECONNRESET transport failures and failed the legitimate-client validity check. These passing runs cap active sessions at 64; they do not validate 500 simultaneous agents. Telemetry is bounded and best effort under load; use the complete result and journal for evidence. Rates include local telemetry flushing and reflect this machine and these short scripted plans only.', '',
  ...rows.flatMap((r) => [`- ${r.count} agents: ${r.result}`, `  - SHA-256: ${r.digest}`]), '',
].join('\n'));
console.log(`Scale assertions passed; evidence: ${note}`);
