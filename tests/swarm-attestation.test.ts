/**
 * Pre-test readiness: the runner must prove which stack it is talking to and
 * which defense mode that stack runs, before it writes a result, a journal or
 * sends any model prompt. Everything runs in-process on loopback; no model,
 * no cloud.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDefense, statusMac, statusRequestToken, STATUS_PATH, STATUS_FORMAT } from '../lab/services/defense/gateway.mjs';
import { createHub } from '../lab/services/swarm/hub.mjs';
import { attestStack, enforceAttestation, summarise, classify, main as runSwarm } from '../experiments/swarm/run.mjs';
import { checkReadiness } from '../experiments/swarm/attest.mjs';
import { isGcpStackId } from '../experiments/swarm/stack-id.mjs';
import { parseKeyFile, attestationArgs } from '../cloud/gcp/dashboard-control.mjs';

const controlKey = 'c'.repeat(64);
const otherKey = 'd'.repeat(64);
const legitKey = 'LABKEY-' + 'A1'.repeat(16);
type Srv = ReturnType<typeof createServer>;
const listen = (srv: Srv) => new Promise<string>((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(srv.address() as { port: number }).port}`)));
const close = (...srvs: Srv[]) => Promise.all(srvs.map((s) => new Promise((r) => { s.closeAllConnections?.(); s.close(r); })));

async function stack(mode: 'baseline' | 'hardened' | 'defended', { key = controlKey, stackId = 'gcp:test-vm:0000abcd' } = {}) {
  const d = createDefense({ mode, stackId, controlKey: key, legitimateKey: legitKey, peerHeader: 'x-lab-peer' });
  const gw = createServer(d.publicHandler);
  const hub = createHub({ upstream: await listen(gw) });
  const hubOrigin = await listen(hub.server);
  return { d, hubOrigin, stop: () => close(gw, hub.server) };
}
const engage = (hubOrigin: string, over: Record<string, unknown> = {}) => {
  const resultsDir = mkdtempSync(join(tmpdir(), 'swarm-attest-'));
  return { resultsDir, run: runSwarm({
    provider: 'scripted', agents: 2, roles: ['legit', 'exploit'], target: hubOrigin, basePath: '/lab', hub: hubOrigin,
    controlKey, legitKey, model: '', seed: 7, budget: {}, sign: false, resultsDir, ...over,
  }) };
};

test('gateway: a control-key holder gets a signed mode/stack attestation; anyone else sees an ordinary unknown path', async () => {
  const s = await stack('defended');
  try {
    const nonce = 'ab'.repeat(16);
    const ok = await fetch(`${s.hubOrigin}/lab${STATUS_PATH}`, { headers: { 'x-lab-status': `${nonce}.${statusRequestToken(controlKey, nonce)}` } });
    assert.equal(ok.status, 200);
    const { mac, ...body } = await ok.json();
    assert.deepEqual({ ...body, issuedAt: typeof body.issuedAt }, { format: STATUS_FORMAT, mode: 'defended', stackId: 'gcp:test-vm:0000abcd', nonce, issuedAt: 'number' });
    assert.equal(mac, statusMac(controlKey, body));
    // No token, a token under another key, or a garbled one: identical to any unknown path.
    const unknown = await fetch(`${s.hubOrigin}/lab/__lab/nothing-here`);
    const expected = { status: unknown.status, body: await unknown.text() };
    for (const header of [undefined, `${nonce}.${statusRequestToken(otherKey, nonce)}`, 'garbage']) {
      const r = await fetch(`${s.hubOrigin}/lab${STATUS_PATH}`, { headers: header ? { 'x-lab-status': header } : {} });
      assert.deepEqual({ status: r.status, body: await r.text() }, expected, `header ${header}`);
    }
  } finally { await s.stop(); }
});

test('attestStack verifies the intended stack and mode through the hub; a stale stack with other keys cannot attest', async () => {
  const s = await stack('defended');
  const stale = await stack('baseline', { key: otherKey, stackId: 'local' });
  try {
    const att = await attestStack({ target: s.hubOrigin, basePath: '/lab', controlKey });
    assert.equal(att.status, 'verified');
    assert.equal(att.mode, 'defended');
    assert.equal(att.stackId, 'gcp:test-vm:0000abcd');
    assert.doesNotThrow(() => enforceAttestation(att, { expectMode: 'defended', expectStack: 'gcp:test-vm:0000abcd' }));
    // The stale stack answers, but not under this engagement's control key.
    const bad = await attestStack({ target: stale.hubOrigin, basePath: '/lab', controlKey });
    assert.equal(bad.status, 'unavailable');
    assert.match(bad.reason!, /HTTP 404/);
    assert.throws(() => enforceAttestation(bad, { expectMode: 'defended' }), /could not be verified/);
  } finally { await s.stop(); await stale.stop(); }
});

test('attestStack rejects forged, replayed, reshaped and off-host answers', async () => {
  const nonce = '12'.repeat(16);
  const body = (n: string, mode = 'defended') => ({ format: STATUS_FORMAT, mode, stackId: 'gcp:x:1', nonce: n, issuedAt: 1 });
  const answer = (payload: unknown) => async () => new Response(JSON.stringify(payload), { status: 200 });
  const replayed = { ...body('ff'.repeat(16)), mac: statusMac(controlKey, body('ff'.repeat(16))) };
  const forged = { ...body(nonce), mac: statusMac(otherKey, body(nonce)) };
  const tampered = { ...body(nonce, 'defended'), mac: statusMac(controlKey, body(nonce, 'baseline')) };
  const extra = { ...body(nonce), note: 'x', mac: statusMac(controlKey, { ...body(nonce), note: 'x' }) };
  for (const [name, payload, re] of [['replayed', replayed, /nonce/], ['forged', forged, /MAC/], ['tampered', tampered, /MAC/], ['reshaped', extra, /shape/]] as const) {
    const att = await attestStack({ target: 'http://127.0.0.1:9', basePath: '/lab', controlKey }, { nonce, fetchImpl: answer(payload) as typeof fetch });
    assert.equal(att.status, 'unavailable', name);
    assert.match(att.reason!, re, name);
  }
  const good = await attestStack({ target: 'http://127.0.0.1:9', basePath: '/lab', controlKey }, { nonce, fetchImpl: answer({ ...body(nonce), mac: statusMac(controlKey, body(nonce)) }) as typeof fetch });
  assert.equal(good.status, 'verified');
  let calls = 0;
  const off = await attestStack({ target: 'http://10.0.0.5:18092', basePath: '/lab', controlKey }, { fetchImpl: (async () => { calls++; return new Response('{}'); }) as typeof fetch });
  assert.equal(off.status, 'unavailable');
  assert.equal(calls, 0, 'nothing is sent to a non-loopback target');
});

test('runner fails closed before writing anything when the stack is stale, in the wrong mode or the wrong stack', async () => {
  const stale = await stack('defended', { key: otherKey });
  const baseline = await stack('baseline');
  const wrongStack = await stack('defended', { stackId: 'local' });
  try {
    const cases: [string, Record<string, unknown>, RegExp][] = [
      [stale.hubOrigin, { expectMode: 'defended' }, /could not be verified/],
      [baseline.hubOrigin, { expectMode: 'defended' }, /DEFENSE_MODE=baseline, expected defended/],
      [wrongStack.hubOrigin, { expectMode: 'defended', expectStack: 'gcp:test-vm:0000abcd' }, /stack id is local, expected gcp:test-vm:0000abcd/],
    ];
    for (const [origin, expect, re] of cases) {
      const { resultsDir, run } = engage(origin, expect);
      await assert.rejects(run, re);
      assert.deepEqual(readdirSync(resultsDir), [], 'no result or journal written');
    }
    assert.ok(!baseline.d.target.state.realExportServed && !wrongStack.d.target.state.realExportServed, 'no agent ran');
  } finally { await stale.stop(); await baseline.stop(); await wrongStack.stop(); }
});

test('an attested defended run records the attestation and is the only kind marked defendedRun', async () => {
  const s = await stack('defended');
  try {
    const { run } = engage(s.hubOrigin, { expectMode: 'defended', expectStack: 'gcp:test-vm:0000abcd' });
    const { summary } = await run;
    assert.equal(summary.validity.interpretable, true, summary.validity.reasons.join('; '));
    assert.equal(summary.validity.defenseMode, 'defended');
    assert.equal(summary.validity.stackId, 'gcp:test-vm:0000abcd');
    assert.equal(summary.validity.defendedRun, true);
  } finally { await s.stop(); }
  // Baseline without expectations: runs, records the mode, never a defended-run result.
  const b = await stack('baseline');
  try {
    const { summary } = await engage(b.hubOrigin).run;
    assert.equal(summary.validity.defenseMode, 'baseline');
    assert.equal(summary.validity.defendedRun, false);
    assert.match(summary.validity.notes.join(), /cannot demonstrate the deception defense/);
  } finally { await b.stop(); }
});

test('a successful legitimate client alone does not make a result interpretable: attestation is required', () => {
  const legit = { kind: 'legit', ...classify({ log: [{ type: 'tool.http', path: '/lab/api/v2/records/export', status: 200 }], result: { stopReason: 'submitted' }, servedExportIds: new Set() }) };
  const red = { kind: 'red', ...classify({ log: [{ type: 'tool.http', path: '/lab/api/v2/records/export', status: 403 }], result: { stopReason: 'budget' }, servedExportIds: new Set() }) };
  for (const attestation of [null, { status: 'unavailable', reason: 'no status attestation (HTTP 404)' }]) {
    const s = summarise([legit, red], { attestation });
    assert.equal(s.efficacy.legitExported, 1);
    assert.equal(s.validity.interpretable, false);
    assert.equal(s.validity.defendedRun, false);
    assert.match(s.validity.reasons.join(), /not attested/);
  }
});

const GCP_ID = 'gcp:test-vm:0000abcd';
const keyFile = (stackLine: string | null, key = controlKey) => `LAB_CONTROL_KEY=${key}\nLAB_LEGIT_KEY=${legitKey}\n${stackLine === null ? '' : `LAB_STACK_ID=${stackLine}\n`}`;

test('stack id rule: only gcp:<host>:<8 hex> labels count as a GCP stack', () => {
  for (const id of [GCP_ID, 'gcp:gatra-deception-demo:ad12ced4']) assert.equal(isGcpStackId(id), true, id);
  for (const id of [undefined, '', 'unlabelled', 'local', 'gcp:', 'gcp:vm', 'gcp:vm:1', 'gcp:vm:ABCDEF12', 'xgcp:vm:0000abcd', 'gcp:vm:0000abcd\n']) assert.equal(isGcpStackId(id), false, String(id));
});

test('dashboard: a VM key file without a GCP LAB_STACK_ID fails closed; runner args always carry --expect-stack', () => {
  for (const line of [null, 'unlabelled', 'local', '']) {
    assert.throws(() => parseKeyFile(keyFile(line)), /LAB_STACK_ID/, String(line));
  }
  const keys = parseKeyFile(keyFile(GCP_ID));
  assert.deepEqual(attestationArgs(keys), ['--expect-mode', 'defended', '--expect-stack', GCP_ID]);
  for (const k of [{}, { stackId: 'unlabelled' }, null]) assert.throws(() => attestationArgs(k), /LAB_STACK_ID/);
});

test('dashboard path: an unlabelled defended stack is refused by the runner before anything is written', async () => {
  const s = await stack('defended', { stackId: 'unlabelled' });
  try {
    const [, mode, , stackId] = attestationArgs(parseKeyFile(keyFile(GCP_ID)));
    const { resultsDir, run } = engage(s.hubOrigin, { expectMode: mode, expectStack: stackId });
    await assert.rejects(run, /stack id is unlabelled, expected gcp:test-vm:0000abcd/);
    assert.deepEqual(readdirSync(resultsDir), []);
    assert.ok(!s.d.target.state.realExportServed, 'no agent ran');
  } finally { await s.stop(); }
});

test('attest.mjs: missing or non-GCP stack ids are NO-GO even when the stack attests defended mode', async () => {
  const unlabelled = await stack('defended', { stackId: 'unlabelled' });
  const gcp = await stack('defended', { stackId: GCP_ID });
  try {
    const no = async (text: string, origin: string, opts: Record<string, string> = {}, re: RegExp) => {
      const r = await checkReadiness(text, { target: origin, ...opts });
      assert.equal(r.go, false, r.message);
      assert.match(r.message, re);
    };
    // The key file has no stack id, or a non-GCP one: NO-GO before any request.
    await no(keyFile(null), unlabelled.hubOrigin, {}, /LAB_STACK_ID is missing/);
    await no(keyFile('unlabelled'), unlabelled.hubOrigin, {}, /"unlabelled" is not a GCP swarm stack id/);
    await no(keyFile(null), unlabelled.hubOrigin, { expectStack: 'unlabelled' }, /--expect-stack "unlabelled"/);
    // The key file names a GCP stack, but the answering stack reports unlabelled.
    await no(keyFile(GCP_ID), unlabelled.hubOrigin, {}, /stack id is unlabelled/);
    const go = await checkReadiness(keyFile(GCP_ID), { target: gcp.hubOrigin });
    assert.equal(go.go, true, go.message);
    assert.match(go.message, /^GO: stack gcp:test-vm:0000abcd attests DEFENSE_MODE=defended/);
    let calls = 0;
    const r = await checkReadiness(keyFile(null), { target: gcp.hubOrigin }, { fetchImpl: (async () => { calls++; return new Response('{}'); }) as typeof fetch });
    assert.equal(r.go, false);
    assert.equal(calls, 0, 'a missing stack id is refused before contacting the stack');
  } finally { await unlabelled.stop(); await gcp.stop(); }
});
