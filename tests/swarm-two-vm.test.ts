/**
 * Two-VM comparison (VM1 baseline vs VM2 defended): each lab gets its own
 * expected mode, stack id and labelled result file, and the same seed yields
 * the same agent mix on both. In-process loopback only; no cloud, no model.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefense } from '../lab/services/defense/gateway.mjs';
import { createHub } from '../lab/services/swarm/hub.mjs';
import { main as runSwarm, parseArgs, validateScale } from '../experiments/swarm/run.mjs';
import { parseKeyFile, attestationArgs, agentLimit, LABS } from '../cloud/gcp/dashboard-control.mjs';

const controlKey = 'c'.repeat(64);
const legitKey = 'LABKEY-' + 'B2'.repeat(16);
type Srv = ReturnType<typeof createServer>;
const listen = (srv: Srv) => new Promise<string>((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(srv.address() as { port: number }).port}`)));
const close = (...srvs: Srv[]) => Promise.all(srvs.map((s) => new Promise((r) => { s.closeAllConnections?.(); s.close(r); })));

async function stack(mode: 'baseline' | 'defended', stackId: string) {
  const d = createDefense({ mode, stackId, controlKey, legitimateKey: legitKey, peerHeader: 'x-lab-peer' });
  const gw = createServer(d.publicHandler);
  const hub = createHub({ upstream: await listen(gw) });
  const hubOrigin = await listen(hub.server);
  return { hubOrigin, stop: () => close(gw, hub.server) };
}

test('labs: VM1 and VM2 use distinct tunnel ports, hub paths and default modes', () => {
  assert.notEqual(LABS.vm1.port, LABS.vm2.port);
  assert.notEqual(LABS.vm1.hubPath, LABS.vm2.hubPath);
  assert.deepEqual([LABS.vm1.mode, LABS.vm2.mode], ['baseline', 'defended']);
});

test('dashboard: key file carries DEFENSE_MODE; attestation expects the lab mode; scripted runs may scale to 1,000 per VM', () => {
  const keys = parseKeyFile(`LAB_CONTROL_KEY=${controlKey}\nLAB_LEGIT_KEY=${legitKey}\nLAB_STACK_ID=gcp:vm1:0000abcd\nDEFENSE_MODE=baseline\n`);
  assert.equal(keys.mode, 'baseline');
  assert.deepEqual(attestationArgs(keys, 'baseline'), ['--expect-mode', 'baseline', '--expect-stack', 'gcp:vm1:0000abcd']);
  assert.deepEqual(attestationArgs(keys), ['--expect-mode', 'defended', '--expect-stack', 'gcp:vm1:0000abcd']);
  assert.throws(() => attestationArgs(keys, 'off'), /unknown defense mode/);
  assert.equal(agentLimit('scripted'), 1000);
  for (const p of ['ollama', 'openai-compatible', 'tantular-cloud']) assert.equal(agentLimit(p), 16);
});

test('runner: --label is validated and kept out of path traversal', () => {
  const base = ['--control-key', controlKey, '--agents', '2'];
  assert.equal((parseArgs([...base, '--label', 'vm2']) as { label?: string }).label, 'vm2');
  for (const bad of ['../x', 'VM1', '', 'a'.repeat(25), 'vm 1']) assert.throws(() => parseArgs([...base, '--label', bad]), /--label/, bad);
});

test('same seed on a baseline VM1 and a defended VM2: same agent mix, distinct labelled results, each attests its own mode', async () => {
  const vm1 = await stack('baseline', 'gcp:vm1:0000aaaa');
  const vm2 = await stack('defended', 'gcp:vm2:0000bbbb');
  const resultsDir = mkdtempSync(join(tmpdir(), 'swarm-two-vm-'));
  try {
    const common = { provider: 'scripted', agents: 20, concurrency: 8, roles: [], basePath: '/lab', controlKey, legitKey, model: '', seed: 1234, budget: {}, sign: false, resultsDir };
    // Run concurrently, as "Run both" does.
    const [r1, r2] = await Promise.all([
      runSwarm({ ...common, label: 'vm1', target: vm1.hubOrigin, hub: vm1.hubOrigin, expectMode: 'baseline', expectStack: 'gcp:vm1:0000aaaa' }),
      runSwarm({ ...common, label: 'vm2', target: vm2.hubOrigin, hub: vm2.hubOrigin, expectMode: 'defended', expectStack: 'gcp:vm2:0000bbbb' }),
    ]);
    const files = readdirSync(resultsDir).filter((f) => f.endsWith('.json'));
    assert.equal(files.filter((f) => f.startsWith('result-swarm-vm1-')).length, 1);
    assert.equal(files.filter((f) => f.startsWith('result-swarm-vm2-')).length, 1);
    const [a, b] = [r1, r2].map((r) => JSON.parse(readFileSync(r.outPath, 'utf8')));
    assert.deepEqual(a.agentsSpec, b.agentsSpec, 'identical agent mix');
    assert.equal(a.seed, b.seed);
    assert.equal(a.summary.validity.defenseMode, 'baseline');
    assert.equal(b.summary.validity.defenseMode, 'defended');
    assert.equal(b.summary.validity.defendedRun, true);
    assert.equal(a.summary.validity.defendedRun, false);
    // Legitimate clients succeed on both; that is what makes the comparison interpretable.
    for (const r of [a, b]) assert.equal(r.summary.efficacy.legitExported, r.summary.efficacy.validLegit);
  } finally { await vm1.stop(); await vm2.stop(); }
});

test('SSH labs: ssh:<host>:<8 hex> stack ids are required for SSH targets and refused for GCP targets', () => {
  const file = (id: string) => `LAB_CONTROL_KEY=${controlKey}\nLAB_LEGIT_KEY=${legitKey}\nLAB_STACK_ID=${id}\nDEFENSE_MODE=defended\n`;
  const keys = parseKeyFile(file('ssh:tantular-ampera:74b0b822'), 'ssh');
  assert.deepEqual(attestationArgs(keys, 'defended', 'ssh'), ['--expect-mode', 'defended', '--expect-stack', 'ssh:tantular-ampera:74b0b822']);
  assert.throws(() => parseKeyFile(file('ssh:tantular-ampera:74b0b822')), /LAB_STACK_ID/, 'GCP target refuses an ssh id');
  for (const bad of ['gcp:vm:0000abcd', 'unlabelled', 'ssh:x:1', 'ssh::0000abcd']) assert.throws(() => parseKeyFile(file(bad), 'ssh'), /LAB_STACK_ID/, bad);
});

test('runner: scripted swarms may use 1..1000 agents per engagement', () => {
  assert.equal(validateScale({ agents: 1000, concurrency: 16 }), 16);
  for (const agents of [0, 1001]) assert.throws(() => validateScale({ agents }), /1\.\.1000/);
});
