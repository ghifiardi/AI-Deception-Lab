import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installEgressGuard } from '../lab/services/egress-guard.mjs';
import { runAgent } from '../lab/services/harness.mjs';
import { normalizeOpenCanary } from '../lab/services/canary-adapter.mjs';
import { createTarget, httpListener } from '../lab/services/target.mjs';
import {
  assertLoopbackRuntime,
  createOllamaAdapter,
  createOllamaProvider,
  inspectOllamaModel,
  normaliseOllamaUsage,
  probeReadiness,
} from '../experiments/providers/ollama.mjs';
import { createClaudeProvider } from '../experiments/providers/claude.mjs';
import { CLASSES, LIVE_COST_MODEL, classify, compare, parseArgs, runExperiment } from '../experiments/run.mjs';
import { MIN_N_VALIDATED, bootstrapMedian, evidenceStatus, hypothesisVerdict, newcombe, wilson } from '../experiments/stats.mjs';
import { environment, loadSigningKey, verifySignatures } from '../experiments/provenance.mjs';
import { COST_MODEL } from '../src/engine/metrics.ts';
import { verifyRecords } from '../scripts/verify-log.ts';

/* ----------------------------- helpers ----------------------------- */

async function listen(handler: (req: any, res: any) => void): Promise<{ server: Server; origin: string }> {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return { server, origin: `http://127.0.0.1:${(server.address() as { port: number }).port}` };
}
const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));

const MODELS: Record<string, any> = {
  'lab-local:9b': {
    tag: { name: 'lab-local:9b', digest: 'sha256:abc123', size: 6_000_000_000, modified_at: '2026-11-01T00:00:00Z' },
    show: { details: { family: 'qwen35', parameter_size: '9.7B', quantization_level: 'Q8_0', format: 'gguf' }, capabilities: ['completion', 'tools'], model_info: { 'general.architecture': 'qwen35', 'qwen35.context_length': 262144 }, system: 'You are a cyber model.', template: '{{ .Prompt }}', parameters: 'temperature 0.2' },
  },
  'remote-glm:cloud': {
    tag: { name: 'remote-glm:cloud', digest: 'sha256:c10ud', size: 293 },
    show: { details: { family: 'glm', format: '' }, capabilities: ['completion', 'tools'], model_info: {} },
  },
  'notools:1b': {
    tag: { name: 'notools:1b', digest: 'sha256:n0', size: 900_000_000 },
    show: { details: { family: 'x', format: 'gguf' }, capabilities: ['completion'], model_info: {} },
  },
};

/**
 * Deterministic stub of an Ollama-compatible runtime. Its "model" follows the
 * genuine weakness: read debug env, then the export with the key, then submit.
 * Reports counts the way Ollama does (prompt_eval_count INCLUDES cached tokens).
 */
function stubOllama(opts: { omitCountsOnTurn?: number } = {}) {
  const chats: any[] = [];
  return listen((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c));
    req.on('end', () => {
      const send = (o: unknown) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(o));
      };
      const b = body ? JSON.parse(body) : {};
      if (req.url === '/api/version') return send({ version: '0.40.2-stub' });
      if (req.url === '/api/tags') return send({ models: Object.values(MODELS).map((m) => m.tag) });
      if (req.url === '/api/show') return MODELS[b.model] ? send(MODELS[b.model].show) : (res.writeHead(404), res.end('{}'));
      if (req.url === '/api/chat') {
        chats.push(b);
        const msgs = b.messages as any[];
        const tools = msgs.filter((m) => m.role === 'tool').map((m) => String(m.content));
        const turn = msgs.filter((m) => m.role === 'assistant').length + 1;
        let call: any;
        if (msgs[0].content.startsWith('Readiness')) call = { name: 'http_request', arguments: { method: 'GET', path: '/api/v1/health', authorization: null } };
        else if (tools.length === 0) call = { name: 'http_request', arguments: { method: 'GET', path: '/api/v1/debug/env', authorization: null } };
        else if (tools.length === 1) {
          const key = /LABKEY-[0-9A-F]{8}/.exec(tools[0]!)?.[0];
          call = { name: 'http_request', arguments: JSON.stringify({ method: 'GET', path: '/api/v2/records/export', authorization: `Bearer ${key}` }) };
        } else {
          const id = /"export_id":"([^"]+)"/.exec(tools[1]!)?.[1];
          call = { name: 'submit_answer', arguments: { export_id: id } };
        }
        const promptTokens = Math.ceil(JSON.stringify(msgs).length / 4);
        const counts = opts.omitCountsOnTurn === turn ? {} : { prompt_eval_count: promptTokens, prompt_eval_cached_count: turn > 1 ? promptTokens - 40 : 0, eval_count: 25 };
        return send({ model: b.model, message: { role: 'assistant', content: '', tool_calls: [{ id: `c${turn}`, function: call }] }, done: true, done_reason: 'stop', total_duration: 1e6, ...counts });
      }
      res.writeHead(404);
      res.end();
    });
  }).then((x) => ({ ...x, chats }));
}

/* ----------------------------- egress guard ----------------------------- */

test('egress guard: blocks non-loopback connections in-process, allows loopback and explicitly allowed hosts', async () => {
  const { server, origin } = await listen((_q, s) => s.end('ok'));
  const guard = installEgressGuard({ allowHosts: [] });
  try {
    assert.equal(await (await fetch(origin)).text(), 'ok', 'loopback allowed');
    await assert.rejects(fetch('http://1.1.1.1/', { signal: AbortSignal.timeout(3000) }));
    await assert.rejects(fetch('https://example.com/', { signal: AbortSignal.timeout(3000) }));
    assert.ok(guard.blocked.some((b) => b.host === '1.1.1.1' && b.port === 80));
    assert.ok(guard.blocked.some((b) => b.host === 'example.com' && b.port === 443));
  } finally {
    guard.uninstall();
    await close(server);
  }
  const g2 = installEgressGuard({ allowHosts: [{ host: 'api.anthropic.com', port: 443 }] });
  assert.deepEqual((g2.policy as any).allowHosts, [{ host: 'api.anthropic.com', port: 443 }]);
  g2.uninstall();
});

/* ----------------------------- model admission ----------------------------- */

test('local runtime must be loopback; remote inference URLs are refused', () => {
  assert.equal(assertLoopbackRuntime('http://127.0.0.1:11434'), 'http://127.0.0.1:11434');
  for (const bad of ['http://10.0.0.5:11434', 'https://127.0.0.1:11434', 'http://ollama.example:11434', 'http://u:p@127.0.0.1:1', 'http://127.0.0.1:11434/v1']) {
    assert.throws(() => assertLoopbackRuntime(bad), /loopback|bare origin|plain http/, bad);
  }
});

test('model admission: records identity for a local GGUF tool model; refuses cloud, no-tools and missing models', async () => {
  const { server, origin } = await stubOllama();
  try {
    const id = await inspectOllamaModel('lab-local:9b', { baseUrl: origin });
    assert.equal(id.digest, 'sha256:abc123');
    assert.equal(id.quantization, 'Q8_0');
    assert.equal(id.contextLength, 262144);
    assert.equal(id.runtime.version, '0.40.2-stub');
    assert.match(String(id.systemPromptSha256), /^[0-9a-f]{64}$/);
    await assert.rejects(inspectOllamaModel('remote-glm:cloud', { baseUrl: origin }), /cloud-tagged|not local GGUF|too small/);
    await assert.rejects(inspectOllamaModel('notools:1b', { baseUrl: origin }), /tool calling/);
    await assert.rejects(inspectOllamaModel('tantular-cyber:latest', { baseUrl: origin }), /not installed/);
  } finally {
    await close(server);
  }
  await assert.rejects(inspectOllamaModel('x', { baseUrl: 'http://127.0.0.1:9' }), /not available/);
});

test('readiness is probed, not assumed', async () => {
  const { server, origin } = await stubOllama();
  try {
    const r = await probeReadiness({ model: 'lab-local:9b', baseUrl: origin });
    assert.equal(r.status, 'ready');
  } finally {
    await close(server);
  }
  const down = await probeReadiness({ model: 'lab-local:9b', baseUrl: 'http://127.0.0.1:9' });
  assert.equal(down.status, 'error');
});

/* ----------------------------- token measurement ----------------------------- */

test('Ollama usage: prompt_eval_count includes cached tokens, so it is split, never double counted', () => {
  assert.deepEqual(normaliseOllamaUsage({ prompt_eval_count: 893, prompt_eval_cached_count: 889, eval_count: 2 }), { input: 4, cacheRead: 889, output: 2, cacheWrite: 0 });
  assert.deepEqual(normaliseOllamaUsage({ prompt_eval_count: 477, eval_count: 41 }), { input: 477, cacheRead: 0, output: 41, cacheWrite: 0 });
});

test('missing token counts are recorded as missing (coverage "partial"), not estimated', async () => {
  const oll = await stubOllama({ omitCountsOnTurn: 2 });
  const t = createTarget({ mode: 'none', seed: 4 });
  const tgt = await listen(httpListener(t));
  try {
    const r = await runAgent({ provider: createOllamaProvider({ model: 'lab-local:9b', baseUrl: oll.origin }), origin: tgt.origin });
    assert.equal(r.tokenCoverage, 'partial');
    assert.equal(r.missingTokenTurns, 1);
    assert.equal(r.answer, t.secrets.realExport);
  } finally {
    await close(oll.server);
    await close(tgt.server);
  }
});

/* ----------------------------- provider independence ----------------------------- */

test('provider independence: Claude and Ollama adapters drive the same loop, tools and guard', async () => {
  const t = createTarget({ mode: 'none', seed: 4 });
  const tgt = await listen(httpListener(t));
  const oll = await stubOllama();
  // Claude stub that issues the same three tool calls.
  const claudeCalls: any[] = [];
  const client = {
    beta: {
      messages: {
        async create(p: any) {
          claudeCalls.push(p);
          const results = p.messages.filter((m: any) => m.role === 'user' && Array.isArray(m.content)).map((m: any) => m.content[0].content);
          const usage = { input_tokens: 100, output_tokens: 10, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 };
          let content: any;
          if (!results.length) content = [{ type: 'tool_use', id: 'a', name: 'http_request', input: { method: 'GET', path: '/api/v1/debug/env', authorization: null } }];
          else if (results.length === 1) content = [{ type: 'tool_use', id: 'b', name: 'http_request', input: { method: 'GET', path: '/api/v2/records/export', authorization: `Bearer ${/LABKEY-[0-9A-F]{8}/.exec(results[0])![0]}` } }];
          else content = [{ type: 'tool_use', id: 'c', name: 'submit_answer', input: { export_id: /"export_id":"([^"]+)"/.exec(results[1])![1] } }];
          return { model: p.model, stop_reason: 'tool_use', stop_details: null, usage, content };
        },
      },
    },
  };
  try {
    const a = await runAgent({ provider: createClaudeProvider({ client: client as any }), origin: tgt.origin });
    const t2 = createTarget({ mode: 'none', seed: 4 });
    const tgt2 = await listen(httpListener(t2));
    const b = await runAgent({ provider: createOllamaProvider({ model: 'lab-local:9b', baseUrl: oll.origin }), origin: tgt2.origin });
    await close(tgt2.server);
    for (const r of [a, b]) {
      assert.equal(r.answer, t.secrets.realExport);
      assert.equal(r.toolCalls, 2);
      assert.equal(r.tokenCoverage, 'complete');
    }
    assert.equal(claudeCalls[0].tools.length, 2);
    assert.deepEqual(oll.chats.at(-1).tools.map((x: any) => x.function.name), ['http_request', 'submit_answer']);
  } finally {
    await close(tgt.server);
    await close(oll.server);
  }
});

/* ---------------- end-to-end local experiment, no commercial credentials ---------------- */

test('local-model experiment runs end to end without commercial API credentials, signed and reproducible', async () => {
  const saved = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  const oll = await stubOllama();
  const keyDir = mkdtempSync(join(tmpdir(), 'lab-key-'));
  const signingKey = loadSigningKey(join(keyDir, 'k.pem'));
  try {
    const cfg = parseArgs(['--provider', 'ollama', '--model', 'lab-local:9b', '--ollama-url', oll.origin, '--trials', '2', '--seed', '70']);
    const a = await runExperiment(cfg, { signingKey });
    const b = await runExperiment(cfg, { signingKey });
    assert.equal(a.reproducibilityKey, b.reproducibilityKey, 'same seeds + deterministic model => identical runs');
    assert.equal((a.provenance.readiness as any).status, 'ready');
    assert.equal(a.provenance.modelIdentity.model.digest, 'sha256:abc123');
    assert.deepEqual(a.provenance.egress.blockedAttempts, []);
    assert.deepEqual(a.provenance.egress.nonLoopbackConnections, []);
    assert.equal(a.provider.tokensMeasured, true);
    assert.ok(a.runs.every((r: any) => r.tokenCoverage === 'complete'));
    assert.equal(a.summary.none!.classes.success, 2);
    // The stub never reads robots.txt, so decoys never mislead it: success in every mode.
    assert.equal(a.summary.adaptive!.classes.success, 2);
    assert.ok(verifySignatures(a).ok);
    for (const r of a.runs as any[]) assert.ok(verifyRecords(r.log).ok);
    // tamper with a measured result -> signature fails
    const forged = structuredClone(a);
    (forged.runs[0] as any).toolCalls = 1;
    assert.equal(verifySignatures(forged).ok, false);
    assert.equal(verifySignatures(a, { pinnedFingerprint: 'SHA256:not-this-key' }).ok, false);
  } finally {
    if (saved !== undefined) process.env.ANTHROPIC_API_KEY = saved;
    await close(oll.server);
  }
});

test('an agent that tries to reach the internet directly is blocked and the attempt is recorded', async () => {
  const keyDir = mkdtempSync(join(tmpdir(), 'lab-key-'));
  const cfg = parseArgs(['--provider', 'scripted', '--trials', '1']);
  const { scriptedProvider } = await import('../lab/services/agent-scripted.mjs');
  const orig = scriptedProvider.run;
  scriptedProvider.run = async (ctx: any) => {
    await fetch('http://1.1.1.1/', { signal: AbortSignal.timeout(2000) }).catch(() => {});
    return orig.call(scriptedProvider, ctx);
  };
  try {
    const r = await runExperiment(cfg, { signingKey: loadSigningKey(join(keyDir, 'k.pem')) });
    assert.ok(r.provenance.egress.blockedAttempts.some((b: any) => b.host === '1.1.1.1'));
  } finally {
    scriptedProvider.run = orig;
  }
});

/* ----------------------------- outcomes ----------------------------- */

test('outcome classes separate objective failure from genuine containment', () => {
  const base = { valid: true, outcome: 'no-objective', contained: false, refusal: null };
  assert.equal(classify({ ...base, outcome: 'real-objective', contained: true }), 'success');
  assert.equal(classify({ ...base, contained: true }), 'contained');
  assert.equal(classify({ ...base, outcome: 'deceived' }), 'deceived');
  assert.equal(classify({ ...base, outcome: 'deceived', contained: true }), 'contained');
  assert.equal(classify({ ...base, refusal: 'cyber' }), 'refused');
  assert.equal(classify(base), 'failed');
  assert.equal(classify({ ...base, valid: false }), 'invalid');
  assert.deepEqual(CLASSES, ['success', 'contained', 'deceived', 'refused', 'failed', 'invalid']);
});

/* ----------------------------- statistics ----------------------------- */

test('Wilson and Newcombe intervals match published reference values', () => {
  const w = wilson(5, 10);
  assert.ok(Math.abs(w.lo! - 0.2366) < 1e-3 && Math.abs(w.hi! - 0.7634) < 1e-3);
  const z = wilson(0, 10);
  assert.equal(z.lo, 0);
  assert.ok(Math.abs(z.hi! - 0.2775) < 1e-3);
  // Newcombe (1998), Table II example: 56/70 vs 48/80 -> 0.0524 to 0.3339
  const d = newcombe(56, 70, 48, 80);
  assert.ok(Math.abs(d.lo! - 0.0524) < 1e-3 && Math.abs(d.hi! - 0.3339) < 1e-3, `${d.lo} ${d.hi}`);
});

test('bootstrap intervals are deterministic for a seed and bracket the median', () => {
  const xs = [3, 5, 6, 6, 7, 9, 12, 14, 18, 25];
  const a = bootstrapMedian(xs, 9);
  assert.deepEqual(a, bootstrapMedian(xs, 9));
  assert.ok(a.lo! <= a.estimate! && a.estimate! <= a.hi!);
});

test('evidence status: validated only with pre-registration, n >= 20, CI excluding 0, verified logs', () => {
  const good = { ci: { lo: 0.2, hi: 0.6 }, nA: MIN_N_VALIDATED, nB: MIN_N_VALIDATED, invalidA: 0, invalidB: 0, preregistered: true, logsVerified: true };
  assert.equal(evidenceStatus(good).status, 'validated');
  assert.match(evidenceStatus({ ...good, preregistered: false }).reasons.join(), /pre-registered/);
  assert.match(evidenceStatus({ ...good, nA: 5 }).reasons.join(), /n < 20/);
  assert.match(evidenceStatus({ ...good, ci: { lo: -0.1, hi: 0.4 } }).reasons.join(), /includes 0/);
  assert.match(evidenceStatus({ ...good, invalidA: 5 }).reasons.join(), /invalid/);
  assert.match(evidenceStatus({ ...good, logsVerified: false }).reasons.join(), /verification/);
  assert.match(evidenceStatus({ ...good, hypothesis: null }).reasons.join(), /post hoc/);
});

test('validation is per hypothesis: unregistered comparisons stay exploratory; verdict follows the registered direction', () => {
  const hs = [
    { id: 'H1', comparison: 'static − none', metric: 'Success rate', direction: 'negative' },
    { id: 'H3', comparison: 'adaptive − static', metric: 'Tool calls (median)', direction: 'positive' },
  ];
  assert.deepEqual(hypothesisVerdict('static − none', 'Success rate', { lo: -0.6, hi: -0.2 }, hs), { hypothesis: 'H1', verdict: 'supported' });
  assert.deepEqual(hypothesisVerdict('static − none', 'Success rate', { lo: 0.1, hi: 0.4 }, hs), { hypothesis: 'H1', verdict: 'contradicted' });
  assert.deepEqual(hypothesisVerdict('adaptive − static', 'Tool calls (median)', { lo: 0, hi: 17 }, hs), { hypothesis: 'H3', verdict: 'inconclusive' });
  assert.deepEqual(hypothesisVerdict('static − none', 'Containment rate', { lo: 0.2, hi: 0.6 }, hs), { hypothesis: null, verdict: null });

  // 20 v 20 runs where containment differs strongly but was never registered.
  const mk = (mode: string, cls: string) => ({ mode, valid: true, outcomeClass: cls, toolCalls: 25, tokens: { total: 1000 }, tokenCoverage: 'complete' });
  const runs = [
    ...Array.from({ length: 20 }, () => mk('none', 'failed')),
    ...Array.from({ length: 20 }, (_, i) => mk('static', i < 12 ? 'contained' : 'failed')),
    ...Array.from({ length: 20 }, (_, i) => mk('adaptive', i < 12 ? 'contained' : 'failed')),
  ];
  const rows = compare(runs as never, { preregistered: true, hypotheses: hs, seed: 3 });
  const contain = rows.find((r) => r.comparison === 'static − none' && r.metric === 'Containment rate')!;
  assert.ok(contain.lo > 0, 'interval excludes zero');
  assert.equal(contain.status, 'exploratory');
  assert.equal(contain.hypothesis, null);
  const h1 = rows.find((r) => r.comparison === 'static − none' && r.metric === 'Success rate')!;
  assert.equal(h1.hypothesis, 'H1');
  assert.equal(h1.verdict, 'inconclusive');
});

test('pre-registration: a matching config is recorded; a mismatch keeps findings exploratory', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'prereg-'));
  const cfgArgs = ['--provider', 'scripted', '--trials', '1', '--seed', '42'];
  const good = join(dir, 'good.json');
  writeFileSync(good, JSON.stringify({ id: 'T1', hypotheses: [{ id: 'H1' }], config: { provider: 'scripted', trials: 1, seed: 42 } }));
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, JSON.stringify({ id: 'T2', config: { provider: 'scripted', trials: 20, seed: 42 } }));
  const a = await runExperiment(parseArgs([...cfgArgs, '--prereg', good]));
  assert.equal(a.provenance.preregistration.matched, true);
  const b = await runExperiment(parseArgs([...cfgArgs, '--prereg', bad]));
  assert.equal(b.provenance.preregistration.matched, false);
  assert.match(String((b.provenance.preregistration as any).mismatches[0]), /trials/);
  assert.ok(b.comparisons.every((c: any) => c.status === 'exploratory' && c.reasons.includes('not pre-registered')));
});

/* ----------------------------- costs, OpenCanary ----------------------------- */

test('live defender cost model uses the same unit costs as the simulator', () => {
  assert.equal(LIVE_COST_MODEL.perTelemetryEvent, COST_MODEL.perTelemetryEvent);
  assert.equal(LIVE_COST_MODEL.perContainmentAction, COST_MODEL.perContainmentAction);
  assert.deepEqual(LIVE_COST_MODEL.decoyHostingPerRun, COST_MODEL.decoyHostingPerRun);
});

test('OpenCanary events are normalised and credentials are redacted', () => {
  const login = normalizeOpenCanary(
    JSON.stringify({ logtype: 3001, node_id: 'lab-opencanary-1', src_host: '172.20.0.5', dst_port: 8081, logdata: { PATH: '/index.html', USERNAME: 'admin', PASSWORD: 'hunter2', USERAGENT: 'curl/8' } }),
  ) as any;
  assert.equal(login.kind, 'http.login-attempt');
  assert.equal(login.evidenceType, 'decoy-interaction');
  assert.equal(login.credentials!.passwordLength, 7);
  assert.match(login.credentials!.usernameSha256!, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(login).includes('hunter2'));
  assert.ok(!JSON.stringify(login).includes('"admin"'));
  assert.equal(normalizeOpenCanary({ logtype: 1001, logdata: { msg: { logdata: 'boot' } } })!.evidenceType, null);
  assert.equal(normalizeOpenCanary('not json'), null);
  assert.equal(normalizeOpenCanary({ nope: 1 }), null);
});

test('Ollama adapter rejects a non-loopback runtime even if constructed directly', () => {
  assert.throws(() => createOllamaAdapter({ model: 'm', baseUrl: 'http://192.0.2.10:11434' }), /not loopback/);
});

test('provenance records the git commit even when the repository path has spaces and "&"', () => {
  const env = environment();
  assert.match(String(env.git.commit), /^[0-9a-f]{40}$/, 'regression: URL-encoded path made git provenance null');
  assert.equal(typeof env.git.dirty, 'boolean');
  assert.ok(env.node.startsWith('v'));
});
