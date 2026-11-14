import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_POLICY, TELEMETRY_COLLECTOR, evaluateEgress, evaluatePolicy } from '../src/engine/policy.ts';
import { LAB_ACTIONS, executeAction } from '../src/engine/containment.ts';
import { compileRun } from '../src/engine/simulator.ts';

test('egress is default-deny; only the exact collector host:port passes', () => {
  assert.equal(evaluateEgress(DEFAULT_POLICY, TELEMETRY_COLLECTOR).allowed, true);
  assert.equal(evaluateEgress(DEFAULT_POLICY, 'COLLECTOR.deception-lab.internal:4318').allowed, true);
  const denied = [
    '203.0.113.45:443',
    'collector.deception-lab.internal:443',
    'collector.deception-lab.internal.example:4318',
    'evil-collector.deception-lab.internal:4318',
    'collector.deception-lab.internal:4318/path',
    'http://collector.deception-lab.internal:4318',
    '',
    ' : ',
    'ns1.exfil.example:53',
  ];
  for (const d of denied) {
    const v = evaluateEgress(DEFAULT_POLICY, d);
    assert.equal(v.allowed, false, d);
    assert.match(v.reason, /denied/i);
  }
});

test('an empty allow list denies everything, including telemetry', () => {
  const locked = { ...DEFAULT_POLICY, egress: { default: 'deny' as const, allow: [] } };
  assert.equal(evaluateEgress(locked, TELEMETRY_COLLECTOR).allowed, false);
});

test('approved-source safeguard is final and outranks containment rules', () => {
  const m = evaluatePolicy(DEFAULT_POLICY, {
    evidenceType: 'canary-use',
    confidence: 0.99,
    evidenceCount: 1,
    sourceLabel: 'vuln-scanner-01',
  });
  assert.deepEqual(m.map((r) => r.rule.id), ['R-SAFE-00']);
  assert.equal(m[0]!.rule.mode, 'approval');
});

test('canary use matches auto lab containment plus a dry-run external proposal', () => {
  const m = evaluatePolicy(DEFAULT_POLICY, {
    evidenceType: 'canary-use',
    confidence: 0.98,
    evidenceCount: 1,
    sourceLabel: '203.0.113.24',
  });
  assert.deepEqual(m.map((r) => [r.rule.id, r.rule.mode]), [
    ['R-CANARY-01', 'auto'],
    ['R-CANARY-02', 'dry-run'],
  ]);
  assert.ok(m[0]!.trace.some((t) => t.includes('confidence')));
});

test('rate anomaly alone never auto-contains', () => {
  const m = evaluatePolicy(DEFAULT_POLICY, { evidenceType: 'rate-anomaly', confidence: 0.99, evidenceCount: 9, sourceLabel: 'x' });
  assert.ok(m.every((r) => r.rule.mode !== 'auto'));
});

test('disabled rules are skipped (policy is configurable)', () => {
  const p = { ...DEFAULT_POLICY, rules: DEFAULT_POLICY.rules.map((r) => (r.id === 'R-CANARY-01' ? { ...r, enabled: false } : r)) };
  const m = evaluatePolicy(p, { evidenceType: 'canary-use', confidence: 0.98, evidenceCount: 1, sourceLabel: 'x' });
  assert.deepEqual(m.map((r) => r.rule.id), ['R-CANARY-02']);
});

test('containment safety: only lab actions on lab targets execute', () => {
  assert.equal(executeAction({ type: 'terminate_session', target: 'lab-sess-a1' }).status, 'executed');
  assert.equal(executeAction({ type: 'quarantine_workload', target: 'hp-api' }).status, 'executed');
  assert.equal(executeAction({ type: 'block_lab_egress', target: 'egress-gw' }).status, 'executed');

  const refused = [
    { type: 'modify_production_firewall', target: 'prod-fw-01' },
    { type: 'block_ip', target: '203.0.113.24' },
    { type: 'terminate_session', target: 'prod-sess-1' },
    { type: 'terminate_session', target: '203.0.113.24' },
    { type: 'quarantine_workload', target: 'core-banking-db' },
    { type: 'quarantine_workload', target: 'egress-gw' },
    { type: 'block_lab_egress', target: 'corp-egress' },
    { type: 'throttle_requests', target: 'lab-sess-A1; rm -rf /' },
  ];
  for (const r of refused) assert.equal(executeAction(r).status, 'refused', JSON.stringify(r));
});

test('external block proposals are always dry-run, even if asked to execute', () => {
  const r = executeAction({ type: 'propose_external_block', target: '203.0.113.24', dryRun: false });
  assert.equal(r.status, 'dry-run');
  assert.match(r.detail, /requires human authorisation/);
});

test('lab action set is exactly the four documented actions', () => {
  assert.deepEqual([...LAB_ACTIONS].sort(), ['block_lab_egress', 'quarantine_workload', 'terminate_session', 'throttle_requests']);
});

test('no compiled run ever executes a non-lab action or a proposal', () => {
  for (const scenario of ['api-canary', 'false-positive', 'agentic-decoy', 'egress-block'] as const) {
    for (const mode of ['none', 'static', 'adaptive'] as const) {
      for (let seed = 1; seed <= 10; seed++) {
        for (const e of compileRun({ scenario, mode, seed }).events) {
          if (e.kind !== 'containment.result' || e.data?.status !== 'executed') continue;
          assert.ok((LAB_ACTIONS as readonly string[]).includes(e.action!), `${scenario}/${mode}: ${e.action}`);
          assert.notEqual(e.dryRun, true);
        }
      }
    }
  }
});
