import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileRun } from '../src/engine/simulator.ts';
import { compareModes, computeMetrics } from '../src/engine/metrics.ts';
import { DEFAULT_POLICY } from '../src/engine/policy.ts';
import type { LabEvent } from '../src/engine/types.ts';

const kinds = (evs: LabEvent[]) => evs.map((e) => e.kind);

test('canary interaction yields evidence and an explainable containment decision (seeds 1–25)', () => {
  for (const mode of ['static', 'adaptive'] as const) {
    for (let seed = 1; seed <= 25; seed++) {
      const { events } = compileRun({ scenario: 'api-canary', mode, seed });
      const used = events.find((e) => e.kind === 'canary.used');
      assert.ok(used, `canary used (${mode}, ${seed})`);
      const decision = events.find((e) => e.kind === 'policy.decision' && e.ruleId === 'R-CANARY-01');
      assert.ok(decision?.evidence?.id.startsWith('EV-A-'));
      assert.equal(decision?.evidence?.type, 'canary-use');
      assert.ok(decision?.rationale && decision.rationale.length > 40);
      assert.ok(String(decision?.data?.trace).includes('confidence'));
      const terminated = events.find((e) => e.kind === 'containment.result' && e.action === 'terminate_session' && e.data?.status === 'executed');
      assert.ok(terminated && terminated.t > used!.t);
      const proposal = events.find((e) => e.kind === 'containment.result' && e.ruleId === 'R-CANARY-02');
      assert.equal(proposal?.data?.status, 'dry-run');
      assert.equal(computeMetrics(compileRun({ scenario: 'api-canary', mode, seed })).objectivesCompleted, 0);
    }
  }
});

test('simulated egress attempts are denied and visibly logged; telemetry stays allowed', () => {
  for (const mode of ['none', 'static', 'adaptive'] as const) {
    const { events } = compileRun({ scenario: 'egress-block', mode, seed: 42 });
    const attempts = events.filter((e) => e.kind === 'egress.attempt');
    const denied = events.filter((e) => e.kind === 'egress.denied');
    assert.equal(attempts.length, 3);
    assert.equal(denied.length, 3);
    for (const d of denied) assert.match(d.rationale ?? '', /denied/i);
    assert.equal(events.filter((e) => e.kind === 'egress.allowed').length, 1, 'only telemetry channel check is allowed');
    assert.equal(events.find((e) => e.kind === 'egress.allowed')?.data?.telemetry, true);
    assert.ok(kinds(events).includes('telemetry.ingest'));
    const m = computeMetrics(compileRun({ scenario: 'egress-block', mode, seed: 42 }));
    assert.equal(m.egressDenied, 3);
    assert.equal(m.taskCompletion, 0);
  }
});

test('token metrics are unavailable (null) unless the attacker is instrumented', () => {
  for (const scenario of ['api-canary', 'false-positive', 'egress-block'] as const) {
    for (const row of compareModes(scenario, 42)) assert.equal(row.metrics.attackerTokens, null, `${scenario}/${row.mode}`);
  }
  for (const row of compareModes('agentic-decoy', 42)) assert.equal(typeof row.metrics.attackerTokens, 'number');
  const { events } = compileRun({ scenario: 'api-canary', mode: 'static', seed: 42 });
  assert.ok(events.every((e) => e.data?.tokens === undefined));
});

test('instrumented agent never exceeds its declared budget (seeds 1–50)', () => {
  for (const mode of ['none', 'static', 'adaptive'] as const) {
    for (let seed = 1; seed <= 50; seed++) {
      const run = compileRun({ scenario: 'agentic-decoy', mode, seed });
      const b = run.fixture.budget!;
      const steps = run.events.filter((e) => e.kind === 'attacker.request' || e.kind === 'attacker.reasoning');
      const tokens = steps.reduce((s, e) => s + Number(e.data?.tokens ?? 0), 0);
      assert.ok(steps.length <= b.maxSteps, `steps ${steps.length}`);
      assert.ok(tokens <= b.maxTokens, `tokens ${tokens}`);
      assert.ok(steps.every((e) => e.t <= b.maxSimMs));
    }
  }
});

test('adaptive decoys raise measured agent effort in this fixture (hypothesis, not guarantee)', () => {
  const [none, , adaptive] = compareModes('agentic-decoy', 42);
  assert.ok(adaptive!.metrics.attackerTokens! > none!.metrics.attackerTokens!);
  assert.ok(adaptive!.metrics.decoyInteractions > 0);
  assert.equal(adaptive!.metrics.taskCompletion, 0);
  const run = compileRun({ scenario: 'agentic-decoy', mode: 'adaptive', seed: 42 });
  assert.ok(run.events.some((e) => e.kind === 'budget.exhausted' || e.kind === 'attacker.halted'));
});

test('AI attribution is never inferred for uninstrumented actors', () => {
  for (const scenario of ['api-canary', 'false-positive', 'egress-block'] as const) {
    for (const mode of ['none', 'static', 'adaptive'] as const) {
      const c = compileRun({ scenario, mode, seed: 3 }).events.find((e) => e.kind === 'actor.classification');
      assert.ok(c);
      assert.equal(c!.data?.aiAttribution, 'not-attributed');
      assert.equal(c!.basis, 'inferred');
    }
  }
  const c = compileRun({ scenario: 'agentic-decoy', mode: 'adaptive', seed: 3 }).events.find((e) => e.kind === 'actor.classification');
  assert.equal(c!.basis, 'observed');
  assert.equal(c!.data?.aiAttribution, 'confirmed-by-instrumentation');
});

test('false-positive safeguard: approved scanner is never disrupted; disabling it shows the impact', () => {
  for (const row of compareModes('false-positive', 42)) {
    assert.equal(row.metrics.benignDisruptions, 0, row.mode);
    assert.equal(row.metrics.taskCompletion, 1, 'scan completes');
  }
  const run = compileRun({ scenario: 'false-positive', mode: 'static', seed: 42 });
  assert.ok(run.events.some((e) => e.kind === 'approval.denied' && e.ruleId === 'R-SAFE-00'));

  const noSafeguard = { ...DEFAULT_POLICY, rules: DEFAULT_POLICY.rules.map((r) => (r.id === 'R-SAFE-00' ? { ...r, enabled: false } : r)) };
  const m = computeMetrics(compileRun({ scenario: 'false-positive', mode: 'static', seed: 42, policy: noSafeguard }));
  assert.ok(m.benignDisruptions > 0);
});

test('metrics are derived consistently from the log', () => {
  const run = compileRun({ scenario: 'api-canary', mode: 'none', seed: 42 });
  const m = computeMetrics(run);
  assert.equal(m.toolCalls, run.events.filter((e) => e.kind === 'attacker.request').length);
  assert.equal(m.decoyInteractions, 0);
  assert.equal(m.taskCompletion, 1, 'without deception the scripted client reaches its objective');
  assert.ok(m.defenderCost >= 0);
  assert.equal(m.dryRunProposals, 0);
});

test('lab source contains no network APIs (default demo is offline)', () => {
  const root = fileURLToPath(new URL('../src/', import.meta.url));
  const files: string[] = [];
  const walk = (d: string) => {
    for (const f of readdirSync(d)) {
      const p = join(d, f);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|css|html)$/.test(f)) files.push(p);
    }
  };
  walk(root);
  assert.ok(files.length > 5);
  // Opt-in network modules, each used only after an explicit operator action:
  // the Live tab (hub URL, loopback by default), the GCP Lab tab (local dashboard
  // API) and recorded-run replay (local dashboard API, read-only). Everything
  // else, including the default simulator, stays offline.
  const optIn = ['/ui/live.ts', '/ui/operator.ts', '/ui/recorded.ts'];
  const offline = files.filter((f) => !optIn.some((m) => f.endsWith(m)));
  assert.equal(offline.length, files.length - optIn.length, 'every opt-in module exists');
  const banned = /\b(fetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|navigator\.connection|https?:\/\/(?!www\.w3\.org))/;
  for (const f of offline) assert.doesNotMatch(readFileSync(f, 'utf8'), banned, f);
  const live = readFileSync(join(root, 'ui/live.ts'), 'utf8');
  // Default is the same-origin /hub proxy; the proxy itself must target loopback.
  assert.match(live, /const DEFAULT_HUB = '\/hub(?:\/vm[12])?';/, 'live tab default hub must be the same-origin proxy');
  assert.match(live, /if \(!isAllowedHub\(base\)\)/, 'live tab must refuse non-loopback hubs before connecting');
  const vite = readFileSync(fileURLToPath(new URL('../vite.config.ts', import.meta.url)), 'utf8');
  // Every /hub proxy (legacy /hub and the per-VM /hub/vm1, /hub/vm2) must target loopback.
  const hubProxies = [...vite.matchAll(/'([^']*\/hub[^']*)': \{ target: '([^']+)'/g)];
  assert.ok(hubProxies.length >= 1, 'hub proxy configured');
  for (const [, key, target] of hubProxies) assert.match(target!, /^http:\/\/127\.0\.0\.1:\d+$/, `hub proxy ${key} must target loopback`);
});
