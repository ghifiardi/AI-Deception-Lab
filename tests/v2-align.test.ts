/**
 * Simulated tab <-> live lab alignment.
 *
 * The browser's "Swarm vs Defense V2" scenario must predict exactly what the real
 * gateway (lab/services/defense/gateway.mjs) does to each swarm role, in every
 * DEFENSE_MODE. And a recorded result file must replay as a verified chain whose
 * requests, statuses and outcomes are the file's own. In-process loopback only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefense, parseEgressDest } from '../lab/services/defense/gateway.mjs';
import { createHub } from '../lab/services/swarm/hub.mjs';
import { main as runSwarm } from '../experiments/swarm/run.mjs';
import { resultFileOk, compactResult } from '../cloud/gcp/dashboard-control.mjs';
import { verifyChain } from '../src/engine/hash.ts';
import { compileRun } from '../src/engine/simulator.ts';
import { V2_MODES, V2_MODE_FOR, V2_ROLES, compileRecordedV2, parseRecorded, sampleAgents, simulateV2Swarm } from '../src/engine/v2.ts';
import type { V2Mode } from '../src/engine/v2.ts';

const controlKey = 'c'.repeat(64);
const legitKey = 'LABKEY-' + 'B2'.repeat(16);
type Srv = ReturnType<typeof createServer>;
const listen = (srv: Srv) => new Promise<string>((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(srv.address() as { port: number }).port}`)));
const close = (...srvs: Srv[]) => Promise.all(srvs.map((s) => new Promise((r) => { s.closeAllConnections?.(); s.close(r); })));

async function realRun(mode: V2Mode, agents: number) {
  const stackId = `gcp:align-${mode}:0000abcd`;
  const d = createDefense({ mode, stackId, controlKey, legitimateKey: legitKey, peerHeader: 'x-lab-peer' });
  const gw = createServer(d.publicHandler);
  const hub = createHub({ upstream: await listen(gw) });
  const origin = await listen(hub.server);
  const resultsDir = mkdtempSync(join(tmpdir(), 'v2-align-'));
  try {
    const r = await runSwarm({ provider: 'scripted', agents, concurrency: 4, roles: [], basePath: '/lab', controlKey, legitKey, model: '', seed: 7, budget: {}, sign: false, resultsDir, label: 'vm1', target: origin, hub: origin, expectMode: mode, expectStack: stackId });
    return JSON.parse(readFileSync(r.outPath, 'utf8'));
  } finally { await close(gw, hub.server); }
}

for (const mode of V2_MODES) {
  test(`simulated swarm matches the real V2 gateway call-for-call (DEFENSE_MODE=${mode})`, async () => {
    const recorded = parseRecorded(await realRun(mode, V2_ROLES.length));
    assert.equal(recorded.mode, mode);
    assert.equal(recorded.attested, true);
    const simulated = simulateV2Swarm(mode);
    for (const sim of simulated) {
      const real = recorded.agents.find((a) => a.role === sim.role);
      assert.ok(real, `real run has a ${sim.role} agent`);
      assert.deepEqual(sim.calls.map((c) => [c.path, c.status]), real.calls.map((c) => [c.path, c.status]), `${mode}/${sim.role} requests`);
      assert.equal(sim.outcome, real.outcome, `${mode}/${sim.role} outcome`);
    }
  });
}

test('deception modes map onto DEFENSE_MODE, and the simulated V2 scenario compiles to a verified chain', () => {
  assert.deepEqual(V2_MODE_FOR, { none: 'baseline', static: 'hardened', adaptive: 'defended' });
  const a = compileRun({ scenario: 'swarm-v2', mode: 'adaptive', seed: 42 });
  const b = compileRun({ scenario: 'swarm-v2', mode: 'adaptive', seed: 42 });
  assert.deepEqual(a.events, b.events, 'deterministic');
  assert.ok(verifyChain(a.events).ok);
  assert.equal(a.v2?.mode, 'defended');
  assert.equal(a.v2?.source, 'simulated');
  // Defended: harvest and exploit are revoked, nobody red exports, egress is
  // denied (blocked), legit still exports.
  const out = Object.fromEntries(a.v2!.agents.map((x) => [x.role, x.outcome]));
  assert.deepEqual(out, { recon: 'no-objective', harvest: 'revoked', exploit: 'revoked', bait: 'blocked', egress: 'blocked', legit: 'success' });
  assert.equal(a.events.filter((e) => e.kind === 'containment.result').length, 2);
  // The egress agent's outbound callout is denied, and that denial is not a revocation.
  assert.equal(a.events.filter((e) => e.kind === 'egress.denied').length, 1);
  assert.equal(a.events.filter((e) => e.kind === 'egress.allowed').length, 0);
  // No GATRA analysis/approval steps are invented for V2.
  assert.ok(!a.events.some((e) => ['agent.assessment', 'actor.classification', 'approval.requested'].includes(e.kind)));
  const base = compileRun({ scenario: 'swarm-v2', mode: 'none', seed: 42 });
  assert.equal(base.v2!.agents.find((x) => x.role === 'harvest')!.outcome, 'success', 'baseline leaks the real key via /debug/env');
  // Egress is default-deny in every mode, including baseline.
  assert.equal(base.v2!.agents.find((x) => x.role === 'egress')!.outcome, 'blocked', 'egress denied even with no deception');
});

test('recorded replay: a real result file replays with its own requests, attested mode and totals', async () => {
  const raw = await realRun('defended', 20);
  for (const input of [raw, compactResult(raw)]) {
    const rec = parseRecorded(input, 'result-swarm-vm1-x.json');
    assert.equal(rec.agents.length, 20);
    assert.equal(rec.efficacy?.redCompromised, 0);
    const sample = compileRecordedV2(rec, true);
    assert.ok(verifyChain(sample.events).ok);
    assert.equal(sample.v2.source, 'recorded');
    assert.equal(sample.v2.totalAgents, 20);
    assert.deepEqual(sample.v2.agents, sampleAgents(rec.agents));
    assert.equal(new Set(sample.v2.agents.map((a) => `${a.role}:${a.outcome}`)).size, sample.v2.agents.length, 'one per role x outcome');
    const all = compileRecordedV2(rec, false);
    assert.equal(all.events.filter((e) => e.kind === 'agent.outcome').length, 20);
    const requests = all.events.filter((e) => e.kind === 'attacker.request').length;
    assert.equal(requests, rec.agents.reduce((n, a) => n + a.calls.length, 0), 'every recorded request appears once');
  }
});

test('recorded replay refuses files that are not swarm results', () => {
  assert.throws(() => parseRecorded({ format: 'other' }), /not a swarm engagement/);
  assert.throws(() => parseRecorded({ format: 'gatra/swarm-engagement@1', agents: [] }), /defense mode/);
  assert.throws(() => parseRecorded({ format: 'gatra/swarm-engagement@1', attestation: { mode: 'defended' }, agents: [{ role: 'boss', outcome: 'success' }] }), /unknown role/);
});

test('egress probe: the gateway only accepts documentation-range destinations and denies them all by default', () => {
  // Accept only RFC 5737 ranges and reserved names.
  assert.deepEqual(parseEgressDest('203.0.113.45:443'), { host: '203.0.113.45', port: 443 });
  assert.deepEqual(parseEgressDest('ns1.exfil.example:53'), { host: 'ns1.exfil.example', port: 53 });
  assert.deepEqual(parseEgressDest('collector.deception-lab.internal.example:4318'), { host: 'collector.deception-lab.internal.example', port: 4318 });
  // Reject anything routable, so a probe can never reach a real host.
  for (const bad of ['8.8.8.8:53', 'example.com:443', 'api.anthropic.com:443', '10.0.0.1:80', '203.0.113.45:0', '203.0.113.45:70000', '203.0.113.300:443', 'localhost:22', '', 'x'.repeat(200) + ':1']) {
    assert.equal(parseEgressDest(bad), null, bad);
  }
});

test('egress probe: every outbound callout is denied by the gateway in every mode, and is not a revocation', async () => {
  for (const mode of V2_MODES) {
    const d = createDefense({ mode, stackId: `gcp:egress-${mode}:0000abcd`, controlKey, legitimateKey: legitKey, peerHeader: 'x-lab-peer' });
    const gw = createServer(d.publicHandler);
    const origin = await listen(gw);
    try {
      const res = await fetch(`${origin}/api/v1/egress?dest=203.0.113.45:443`);
      assert.equal(res.status, 403, mode);
      const body = await res.json();
      assert.equal(body.policy, 'default-deny');
      // A bad destination is rejected before any policy decision.
      assert.equal((await fetch(`${origin}/api/v1/egress?dest=api.anthropic.com:443`)).status, 400, mode);
      // The probe never revokes the peer: a following normal request is not 403 "session terminated".
      assert.notEqual((await fetch(`${origin}/healthz`)).status, 403, mode);
      assert.ok(d.log.records.some((e) => e.type === 'defense.egress.denied'), `${mode} emits egress.denied`);
      assert.ok(!d.log.records.some((e) => e.type === 'defense.revoked'), `${mode} does not revoke on egress`);
    } finally { await close(gw); }
  }
});

test('results API only serves swarm result files by exact name', () => {
  assert.ok(resultFileOk('result-swarm-vm2-2026-11-20T03-25-28-744Z.json'));
  assert.ok(resultFileOk('result-swarm-2026-11-15T02-19-05-390Z.json'));
  for (const bad of ['../x.json', 'result-swarm-vm2-x.json.jsonl', 'result-swarm-vm2-2026-11-20T03-25-28-744Z.json/..', '%2e%2e', 'result-swarm-VM2-2026-11-20T03-25-28-744Z.json']) assert.ok(!resultFileOk(bad), bad);
});
