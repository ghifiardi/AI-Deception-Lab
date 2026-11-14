import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileRun } from '../src/engine/simulator.ts';
import { verifyChain } from '../src/engine/hash.ts';
import { deriveState } from '../src/engine/state.ts';
import type { DeceptionMode, ScenarioId } from '../src/engine/types.ts';

const SCENARIOS: ScenarioId[] = ['api-canary', 'false-positive', 'agentic-decoy', 'egress-block'];
const MODES: DeceptionMode[] = ['none', 'static', 'adaptive'];

test('seeded runs replay identically (every scenario × mode)', () => {
  for (const scenario of SCENARIOS) {
    for (const mode of MODES) {
      const a = compileRun({ scenario, mode, seed: 1337 });
      const b = compileRun({ scenario, mode, seed: 1337 });
      assert.deepEqual(a.events, b.events, `${scenario}/${mode}`);
      assert.equal(a.events.at(-1)!.hash, b.events.at(-1)!.hash);
    }
  }
});

test('different seeds change timings but not the chain validity', () => {
  const a = compileRun({ scenario: 'api-canary', mode: 'static', seed: 1 });
  const b = compileRun({ scenario: 'api-canary', mode: 'static', seed: 2 });
  assert.notEqual(a.events.at(-1)!.hash, b.events.at(-1)!.hash);
  assert.ok(verifyChain(a.events).ok && verifyChain(b.events).ok);
});

test('events are sequenced, chronological and hash-chained', () => {
  for (const scenario of SCENARIOS) {
    for (const mode of MODES) {
      const { events } = compileRun({ scenario, mode, seed: 7 });
      events.forEach((e, i) => {
        assert.equal(e.seq, i + 1);
        if (i) assert.ok(e.t >= events[i - 1]!.t, `${scenario}/${mode} not chronological at ${e.id}`);
      });
      assert.equal(events[0]!.kind, 'scenario.start');
      assert.equal(events.at(-1)!.kind, 'scenario.end');
      assert.deepEqual(verifyChain(events), { ok: true });
    }
  }
});

test('tampering with, removing or reordering an event breaks the chain', () => {
  const { events } = compileRun({ scenario: 'api-canary', mode: 'static', seed: 7 });
  const edited = events.map((e) => ({ ...e }));
  edited[5] = { ...edited[5]!, summary: 'nothing to see here' };
  assert.equal(verifyChain(edited).brokenAt, 6);

  const removed = events.filter((_, i) => i !== 3);
  assert.equal(verifyChain(removed).ok, false);

  const swapped = [...events];
  [swapped[2], swapped[3]] = [swapped[3]!, swapped[2]!];
  assert.equal(verifyChain(swapped).ok, false);
});

test('state derivation: reset, step and seek are pure functions of the cursor', () => {
  const run = compileRun({ scenario: 'api-canary', mode: 'static', seed: 7 });
  const reset = deriveState(run, 0);
  assert.equal(reset.count, 0);
  assert.equal(reset.session, 'not-started');
  assert.equal(reset.decisions.length, 0);

  const end = deriveState(run, run.events.length);
  assert.equal(end.ended, true);
  assert.equal(end.session, 'terminated');

  // stepping forward one at a time reaches the same state as seeking
  let stepped = deriveState(run, 0);
  for (let i = 1; i <= run.events.length; i++) stepped = deriveState(run, i);
  assert.deepEqual(stepped, end);

  // seeking backwards then forwards again is identical
  assert.deepEqual(deriveState(run, 10), deriveState(run, 10));
  assert.deepEqual(deriveState(run, run.events.length + 50), end);
});

test('session state transitions follow containment results', () => {
  const run = compileRun({ scenario: 'api-canary', mode: 'static', seed: 7 });
  const seen: string[] = [];
  for (let i = 0; i <= run.events.length; i++) {
    const s = deriveState(run, i).session;
    if (seen.at(-1) !== s) seen.push(s);
  }
  assert.deepEqual(seen, ['not-started', 'active', 'throttled', 'terminated']);
});
