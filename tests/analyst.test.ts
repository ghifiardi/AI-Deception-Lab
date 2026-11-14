import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileRun, validateAnalystInputs } from '../src/engine/simulator.ts';
import { computeMetrics } from '../src/engine/metrics.ts';
import { verifyChain } from '../src/engine/hash.ts';
import type { AnalystInput } from '../src/engine/types.ts';

const interactive = (inputs: AnalystInput[]) => ({ mode: 'interactive' as const, inputs });

test('interactive mode without inputs leaves approvals pending (no scripted answers leak in)', () => {
  const run = compileRun({ scenario: 'false-positive', mode: 'static', seed: 42, analyst: interactive([]) });
  assert.ok(run.events.some((e) => e.kind === 'approval.requested' && e.ruleId === 'R-SAFE-00'));
  assert.ok(!run.events.some((e) => e.kind.startsWith('approval.') && e.kind !== 'approval.requested'));
  assert.equal(computeMetrics(run).pendingApprovals, 1);
});

test('analyst decisions are explicit chained events and replay identically', () => {
  const req = compileRun({ scenario: 'false-positive', mode: 'static', seed: 42, analyst: interactive([]) }).events.find(
    (e) => e.kind === 'approval.requested',
  )!;
  const inputs: AnalystInput[] = [{ ruleId: 'R-SAFE-00', decision: 'reject', atT: req.t + 2500, note: 'Authorised scan' }];
  const a = compileRun({ scenario: 'false-positive', mode: 'static', seed: 42, analyst: interactive(inputs) });
  const b = compileRun({ scenario: 'false-positive', mode: 'static', seed: 42, analyst: interactive(structuredClone(inputs)) });
  assert.deepEqual(a.events, b.events);
  assert.ok(verifyChain(a.events).ok);
  const d = a.events.find((e) => e.kind === 'approval.denied')!;
  assert.equal(d.t, req.t + 2500);
  assert.equal(d.data?.source, 'interactive');
  assert.equal(d.data?.inputIndex, 0);
  assert.equal(d.rationale, 'Authorised scan');
});

test('adding a decision never changes events before it (UI can continue seamlessly)', () => {
  const base = compileRun({ scenario: 'api-canary', mode: 'none', seed: 42, analyst: interactive([]) });
  const req = base.events.find((e) => e.kind === 'approval.requested')!;
  const atT = req.t + 1000;
  const after = compileRun({
    scenario: 'api-canary',
    mode: 'none',
    seed: 42,
    analyst: interactive([{ ruleId: req.ruleId!, decision: 'approve', atT }]),
  });
  const prefix = base.events.filter((e) => e.t < atT).length;
  assert.deepEqual(after.events.slice(0, prefix), base.events.slice(0, prefix));
  assert.ok(after.events.some((e) => e.kind === 'containment.result' && e.action === 'throttle_requests'));
});

test('approve executes, reject does not, observe defers and lets the rule ask again', () => {
  const policyOff = undefined;
  const firstReq = compileRun({ scenario: 'agentic-decoy', mode: 'adaptive', seed: 42, analyst: interactive([]), policy: policyOff })
    .events.find((e) => e.kind === 'approval.requested' && e.ruleId === 'R-DECOY-02')!;
  assert.ok(firstReq, 'R-DECOY-02 asks for approval');

  const approve = compileRun({
    scenario: 'agentic-decoy',
    mode: 'adaptive',
    seed: 42,
    analyst: interactive([{ ruleId: 'R-DECOY-02', decision: 'approve', atT: firstReq.t + 200 }]),
  });
  assert.ok(approve.events.some((e) => e.kind === 'containment.result' && e.ruleId === 'R-DECOY-02' && e.data?.status === 'executed'));

  const reject = compileRun({
    scenario: 'agentic-decoy',
    mode: 'adaptive',
    seed: 42,
    analyst: interactive([{ ruleId: 'R-DECOY-02', decision: 'reject', atT: firstReq.t + 200 }]),
  });
  assert.ok(!reject.events.some((e) => e.kind === 'containment.action' && e.ruleId === 'R-DECOY-02'));

  const observe = compileRun({
    scenario: 'agentic-decoy',
    mode: 'adaptive',
    seed: 42,
    analyst: interactive([{ ruleId: 'R-DECOY-02', decision: 'observe', atT: firstReq.t + 200 }]),
  });
  const deferred = observe.events.find((e) => e.kind === 'approval.deferred');
  assert.ok(deferred);
  const reasked = observe.events.filter((e) => e.kind === 'approval.requested' && e.ruleId === 'R-DECOY-02');
  assert.equal(reasked.length, 2, 'rule asks again after new evidence');
  assert.ok(reasked[1]!.t > deferred!.t);
  assert.ok(!observe.events.some((e) => e.kind === 'containment.action' && e.ruleId === 'R-DECOY-02'));
});

test('invalid analyst inputs are rejected', () => {
  assert.deepEqual(validateAnalystInputs([{ ruleId: 'R-SAFE-00', decision: 'approve', atT: 10 }]), []);
  const bad = [
    { ruleId: 'DROP TABLE', decision: 'approve', atT: 1 },
    { ruleId: 'R-SAFE-00', decision: 'execute', atT: 1 },
    { ruleId: 'R-SAFE-00', decision: 'approve', atT: -5 },
    { ruleId: 'R-SAFE-00', decision: 'approve', atT: Number.NaN },
    { ruleId: 'R-SAFE-00', decision: 'approve', atT: 1, note: 'x'.repeat(500) },
  ] as unknown as AnalystInput[];
  assert.equal(validateAnalystInputs(bad).length, 5);
  assert.throws(() => compileRun({ scenario: 'api-canary', mode: 'none', seed: 1, analyst: interactive(bad) }), /Invalid analyst inputs/);
});

test('a decision timed before its request waits for the request (never acts early)', () => {
  const run = compileRun({
    scenario: 'false-positive',
    mode: 'static',
    seed: 42,
    analyst: interactive([{ ruleId: 'R-SAFE-00', decision: 'approve', atT: 0 }]),
  });
  // atT 0 precedes the request, so it does not match it; the approval stays pending.
  assert.ok(!run.events.some((e) => e.kind === 'approval.granted'));
});
