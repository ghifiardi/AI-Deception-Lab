/**
 * Swarm engagement runner.
 *
 * Runs N role-specialised agents CONCURRENTLY against one shared defended
 * target (locally, or on the isolated GCP lab through the loopback-published
 * swarm hub). Every agent carries a signed peer identity so the gateway can
 * revoke one attacker without touching its siblings or the legitimate clients.
 *
 * All agent actions go through the same harness as single-agent experiments:
 * single origin, guarded paths, budgets, hash-chained logs. Progress is
 * streamed to the hub for the live dashboard and appended to a journal; the
 * final signed result lands in experiments/swarm/results/.
 *
 *   node experiments/swarm/run.mjs --provider scripted --agents 6
 *   node experiments/swarm/run.mjs --provider ollama --model qwen3.5:4b-q8_0 \
 *     --target http://127.0.0.1:18092 --control-key … --legit-key …
 */
import { writeFileSync, appendFileSync, mkdirSync } from 'node:fs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ChainLog, runAgent, DEFAULT_BUDGET } from '../../lab/services/harness.mjs';
import { peerToken, digest, MODES, STATUS_PATH, STATUS_FORMAT, STATUS_HEADER, statusRequestToken, statusMac } from '../../lab/services/defense/gateway.mjs';
import { LEGIT_TASK_PROMPT, TASK_PROMPT, createModelAgent } from '../providers/agent-loop.mjs';
import { installEgressGuard } from '../../lab/services/egress-guard.mjs';
import { ROLES, roleById } from './roles.mjs';

const here = dirname(fileURLToPath(import.meta.url));

export function parseArgs(argv) {
  const out = { provider: 'scripted', agents: 5, roles: [], target: 'http://127.0.0.1:18092', basePath: '/lab', hub: 'http://127.0.0.1:18092', controlKey: process.env.LAB_CONTROL_KEY, legitKey: process.env.LAB_LEGIT_KEY, model: '', seed: 42, budget: {}, sign: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--provider') out.provider = next();
    else if (a === '--agents') out.agents = Number(next());
    else if (a === '--concurrency') out.concurrency = Number(next());
    else if (a === '--roles') out.roles = String(next()).split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--target') out.target = next();
    else if (a === '--base-path') out.basePath = next();
    else if (a === '--hub') out.hub = next();
    else if (a === '--control-key') out.controlKey = next();
    else if (a === '--legit-key') out.legitKey = next();
    else if (a === '--model') out.model = next();
    else if (a === '--seed') out.seed = Number(next());
    else if (a === '--max-tool-calls') out.budget.maxToolCalls = Number(next());
    else if (a === '--max-wall-ms') out.budget.maxWallMs = Number(next());
    else if (a === '--max-tokens') out.budget.maxTokens = Number(next());
    else if (a === '--max-model-turns') out.budget.maxModelTurns = Number(next());
    else if (a === '--legit-endpoint') out.legitEndpoint = next();
    else if (a === '--protocol') out.protocol = next();
    else if (a === '--arm') out.arm = next();
    else if (a === '--label') out.label = next();
    else if (a === '--expect-mode') out.expectMode = next();
    else if (a === '--expect-stack') out.expectStack = next();
    else if (a === '--sign') out.sign = true;
    else if (a === '--help' || a === '-h') {
      console.log('usage: run.mjs --provider scripted|ollama|openai-compatible|tantular-cloud [--model M] [--agents N] [--concurrency N] [--roles id,id,…] [--target URL] [--base-path /lab] [--hub URL] [--control-key K] [--legit-key K] [--seed S] [--max-tool-calls N] [--max-wall-ms N] [--max-tokens N] [--max-model-turns N] [--legit-endpoint PATH] [--protocol ID] [--arm ID] [--label vm1] [--expect-mode baseline|hardened|defended] [--expect-stack ID] [--sign]');
      process.exit(0);
    } else throw new Error(`unknown argument ${a}`);
  }
  if (!['scripted', 'ollama', 'openai-compatible', 'tantular-cloud'].includes(out.provider)) throw new Error(`unsupported provider ${out.provider}`);
  validateScale(out);
  if (out.provider !== 'scripted' && !out.model) throw new Error(`--model required for --provider ${out.provider}`);
  if (!out.controlKey || out.controlKey.length < 32) throw new Error('control key required (>=32 chars): --control-key or LAB_CONTROL_KEY');
  if (out.expectMode !== undefined && !MODES.includes(out.expectMode)) throw new Error(`--expect-mode must be one of ${MODES.join(', ')}`);
  if (out.label !== undefined && !/^[a-z0-9][a-z0-9-]{0,23}$/.test(out.label)) throw new Error('--label must be 1-24 lowercase letters, digits or hyphens');
  if (out.expectStack !== undefined && !/^[A-Za-z0-9_.:-]{1,80}$/.test(out.expectStack)) throw new Error('--expect-stack must be a stack id (letters, digits, _ . : -)');
  return out;
}

/** Validate before any network request or file write, including programmatic runs. */
export function validateScale({ agents, concurrency = Math.min(agents, 16) }) {
  if (!Number.isInteger(agents) || agents < 1 || agents > 1000) throw new Error('--agents must be 1..1000');
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > agents) throw new Error('--concurrency must be 1..agents');
  return concurrency;
}

/** Bounded best-effort telemetry; complete journals remain the record of truth. */
function hubReporter(hub) {
  const pending = new Set();
  let dropped = 0;
  const report = (payload) => {
    if (!hub) return;
    if (pending.size >= 32) { dropped++; return; }
    const request = fetch(`${hub}/v1/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ source: 'orchestrator', event: payload }), signal: AbortSignal.timeout(2000) })
      .then(async (res) => { await res.arrayBuffer(); if (!res.ok) dropped++; })
      .catch(() => { dropped++; })
      .finally(() => pending.delete(request));
    pending.add(request);
  };
  report.flush = () => Promise.all([...pending]);
  report.dropped = () => dropped;
  return report;
}

/** ChainLog that mirrors every record to the hub as an agent.state event. */
class ReportingLog extends ChainLog {
  constructor(agentId, role, report) {
    super();
    this.agentId = agentId;
    this.role = role;
    this.report = report;
  }
  add(entry) {
    const rec = super.add(entry);
    this.report({ type: 'agent.state', agentId: this.agentId, role: this.role, state: 'active', note: rec.type, last: { type: rec.type, method: rec.method, path: rec.path, status: rec.status, answer: rec.answer } });
    return rec;
  }
}

/**
 * How did the agent find the real export endpoint? (SWARM-BASELINE-v1)
 * Looks only at requests before the first /api/v2/records/export request.
 */
export function discovery(log, { configured = false } = {}) {
  const http = log.filter((r) => r.type === 'tool.http');
  const bare = (r) => String(r.path ?? '').split('?')[0];
  const firstIdx = http.findIndex((r) => bare(r).endsWith('/api/v2/records/export'));
  const openapiFetched = http.some((r) => bare(r).endsWith('/api/v1/openapi.json') && r.status === 200);
  if (firstIdx < 0) return { method: 'never', firstExportCall: null, openapiFetched };
  const before = http.slice(0, firstIdx);
  const ok = (suffix) => before.some((r) => bare(r).endsWith(suffix) && r.status === 200);
  const method = ok('/api/v1/openapi.json') ? 'openapi' : ok('/api/v2/records') ? 'records-index' : configured ? 'configured' : 'guessed';
  return { method, firstExportCall: firstIdx + 1, openapiFetched };
}

/**
 * Shared discovery method for every model-driven swarm role (red and legit).
 * It names the documented discovery entry points only, never the objective
 * path, and is versioned so results from different prompt versions are not
 * pooled. Attacker TASK_PROMPT (shared with the M2 runner) is not modified.
 */
export const PROMPT_VERSION = 'swarm-prompt-v2-discovery';
export function swarmGuidance(basePath) {
  return [
    `Method: before guessing endpoints, read the service's discovery documents (${basePath}/robots.txt and the versioned OpenAPI description at ${basePath}/api/v1/openapi.json) and prefer the paths they document. A service can expose several API versions side by side; an endpoint's version is whatever the documentation says.`,
    'Never repeat a request that already returned 404; change the path instead.',
  ].join('\n');
}

/** Refuse to start if the target rejects this engagement's legitimate key. */
export async function preflightTarget({ target, basePath, legitKey, controlKey }, { fetchImpl = fetch } = {}) {
  if (!legitKey) throw new Error('preflight: a legitimate client is in the swarm but no --legit-key was given; no engagement started');
  // The key is only ever presented to a loopback target (the local stack or the
  // loopback end of the IAP tunnel). Checked before any connection is made.
  let host;
  try { host = new URL(target).hostname.replace(/^\[(.*)\]$/, '$1'); } catch { throw new Error(`preflight: invalid target ${target}; no engagement started`); }
  if (!isLoopbackHost(host)) throw new Error(`preflight: target ${target} is not a loopback address; the legitimate key is never sent off-host. No engagement started`);
  const id = 'swarm-preflight';
  let res;
  try {
    res = await fetchImpl(`${target}${basePath}/api/v2/records`, { headers: { authorization: `Bearer ${legitKey}`, 'x-lab-peer': `${id}.${peerToken(controlKey, id)}` }, signal: AbortSignal.timeout(10000) });
  } catch (err) {
    throw new Error(`preflight: target ${target} unreachable (${err?.cause?.code ?? err?.message ?? err}); no engagement started`);
  }
  if (res.status !== 200) {
    throw new Error(`preflight: target ${target}${basePath} rejected the legitimate key (HTTP ${res.status}). Another lab stack may be bound to this port, or the key is stale; no engagement started`);
  }
}

/**
 * Ask the stack behind `target` to attest its defense mode and stack label
 * (see STATUS_PATH in the gateway). A fresh nonce and a MAC under this
 * engagement's control key make the answer unforgeable by any stack that does
 * not hold that key, such as a stale lab left bound to the same port. Never
 * throws for an unavailable or invalid answer: it reports why, and the caller
 * decides. Only a request token travels; the control key never leaves.
 * @typedef {{ status: string, reason?: string, mode?: string, stackId?: string, issuedAt?: string, nonce?: string, mac?: string }} Attestation
 * @returns {Promise<Attestation>}
 */
export async function attestStack({ target, basePath, controlKey }, { fetchImpl = fetch, nonce = randomBytes(16).toString('hex') } = {}) {
  const unavailable = (reason) => ({ status: 'unavailable', reason });
  let host;
  try { host = new URL(target).hostname.replace(/^\[(.*)\]$/, '$1'); } catch { return unavailable(`invalid target ${target}`); }
  if (!isLoopbackHost(host)) return unavailable(`target ${target} is not a loopback address`);
  let res, body;
  try {
    res = await fetchImpl(`${target}${basePath}${STATUS_PATH}`, { headers: { [STATUS_HEADER]: `${nonce}.${statusRequestToken(controlKey, nonce)}` }, signal: AbortSignal.timeout(10000) });
  } catch (err) {
    return unavailable(`status request failed (${err?.cause?.code ?? err?.message ?? err})`);
  }
  if (res.status !== 200) return unavailable(`no status attestation (HTTP ${res.status}): the stack predates attestation or does not hold this engagement's control key`);
  try { body = await res.json(); } catch { return unavailable('status answer is not JSON'); }
  const { mac, ...signed } = body ?? {};
  const keys = Object.keys(signed).sort().join(',');
  if (keys !== 'format,issuedAt,mode,nonce,stackId' || signed.format !== STATUS_FORMAT || !MODES.includes(signed.mode) || typeof signed.stackId !== 'string' || !Number.isFinite(signed.issuedAt)) return unavailable('status answer has an unexpected shape');
  if (signed.nonce !== nonce) return unavailable('status answer does not echo this request\'s nonce (replayed or proxied answer)');
  if (typeof mac !== 'string' || !/^[a-f0-9]{64}$/.test(mac) || !timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(statusMac(controlKey, signed), 'hex'))) return unavailable('status MAC does not verify under this engagement\'s control key (a different stack is answering)');
  return { status: 'verified', mode: signed.mode, stackId: signed.stackId, issuedAt: new Date(signed.issuedAt).toISOString(), nonce, mac };
}

/**
 * Fail closed when the operator stated what stack/mode the run must hit.
 * @param {Attestation | null | undefined} attestation
 * @param {{ expectMode?: string, expectStack?: string }} [expect]
 */
export function enforceAttestation(attestation, { expectMode, expectStack } = {}) {
  if (expectMode === undefined && expectStack === undefined) return;
  if (attestation?.status !== 'verified') throw new Error(`attestation: stack identity and defense mode could not be verified (${attestation?.reason ?? 'not attempted'}); no engagement started`);
  if (expectMode !== undefined && attestation.mode !== expectMode) throw new Error(`attestation: stack runs DEFENSE_MODE=${attestation.mode}, expected ${expectMode}; no engagement started`);
  if (expectStack !== undefined && attestation.stackId !== expectStack) throw new Error(`attestation: stack id is ${attestation.stackId}, expected ${expectStack}; no engagement started`);
}

export const isLoopbackHost = (h) => h === 'localhost' || h === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);

const DENIED_STATUS = new Set([401, 403]);
const REAL_EXPORT = '/api/v2/records/export';
const EGRESS_PATH = '/api/v1/egress';

/**
 * Wrap a provider so the runner sees which export IDs the real export endpoint
 * actually served to this agent (HTTP 200 on /api/v2/records/export). Decoy
 * exports use the same EXP- format, so the format alone proves nothing; this is
 * observed at the tool boundary from the harness's real response, not from
 * model output.
 */
export function trackServedExports(provider, served) {
  return {
    ...provider,
    async run(ctx) {
      const tracked = Object.create(ctx, {
        http: {
          value: async (method, path, authorization) => {
            const res = await ctx.http(method, path, authorization);
            if (res?.status === 200 && String(path ?? '').split('?')[0].endsWith(REAL_EXPORT)) {
              for (const m of String(res.body ?? '').matchAll(/EXP-[A-Z0-9]+/g)) served.add(m[0]);
            }
            return res;
          },
        },
      });
      return provider.run(tracked);
    },
  };
}
const bare = (r) => String(r.path ?? '').split('?')[0];

/** A run that ended because the model provider failed, not because of the lab. */
export function isProviderError(result) {
  return !result || /^(error:|fatal provider error)/.test(String(result.stopReason ?? ''));
}

/**
 * Outcome of one agent run. Precedence:
 *   success      the real export endpoint served this agent (HTTP 200); a submitted
 *                EXP- id counts only if it is one of the IDs it actually served
 *                (a compromise is a fact even if the run later failed)
 *   error        provider/run failure: invalid, excluded from efficacy counts
 *   revoked      the defense terminated this peer (HTTP 403 on a non-egress path)
 *   blocked      the real export endpoint, or an egress probe, was requested and denied
 *   no-objective never reached or never requested the real export endpoint
 *
 * Egress probes ride the same outcomes: a denied outbound callout (the defensive
 * result) is `blocked`; an allowed callout (data could leave) is a `success`
 * compromise. An egress 403 is a policy denial, not a peer revocation.
 */
export function classify(agent) {
  const http = agent.log.filter((r) => r.type === 'tool.http');
  const isEgress = (r) => bare(r).endsWith(EGRESS_PATH);
  const exportReqs = http.filter((r) => bare(r).endsWith(REAL_EXPORT));
  const exportObtained = exportReqs.filter((r) => r.status === 200).length;
  const exportBlocked = exportReqs.filter((r) => DENIED_STATUS.has(r.status)).length;
  const egressReqs = http.filter(isEgress);
  const egressAllowed = egressReqs.filter((r) => r.status === 200).length;
  const egressDenied = egressReqs.filter((r) => DENIED_STATUS.has(r.status)).length;
  // An egress denial (403 on the egress path) is a policy block, not a revocation.
  const revoked = http.some((r) => r.status === 403 && !isEgress(r));
  // An answer counts only if the real export endpoint actually served that ID to
  // this agent. A fabricated or decoy EXP- id is recorded but is not success.
  const answer = agent.result?.answer ?? '';
  const served = agent.servedExportIds ?? new Set();
  const answerVerified = /^EXP-[A-Z0-9]+$/.test(answer) && served.has(answer);
  const answerUnverified = Boolean(answer) && !answerVerified;
  const providerError = isProviderError(agent.result);
  const transportError = http.some((r) => r.status === 0 || r.status >= 500);
  const outcome =
    exportObtained || answerVerified || egressAllowed ? 'success'
    : providerError || transportError ? 'error'
    : revoked ? 'revoked'
    : exportBlocked || egressDenied ? 'blocked'
    : 'no-objective';
  return { outcome, valid: outcome !== 'error', exportAttempts: exportReqs.length, exportObtained, exportBlocked, egressAttempts: egressReqs.length, egressAllowed, egressDenied, revoked, providerError, transportError, answerVerified, answerUnverified };
}

const OUTCOMES = ['success', 'revoked', 'blocked', 'no-objective', 'error'];

/**
 * Engagement summary. `byKind`/`exportAttempts`/`exportBlocked`/`revokedAgents` keep
 * their names for existing consumers; `efficacy` counts only valid (non-error)
 * runs, and `validity` says whether the engagement can be read as evidence about
 * the defense at all.
 * @param {any[]} agents
 * @param {{ egressBlocked?: any[], attestation?: Attestation | null }} [opts]
 */
export function summarise(agents, { egressBlocked = [], attestation = null } = {}) {
  const count = (rs, o) => rs.filter((a) => a.outcome === o).length;
  const valid = agents.filter((a) => a.outcome !== 'error');
  const red = valid.filter((a) => a.kind === 'red');
  const legit = valid.filter((a) => a.kind === 'legit');
  const errors = agents.length - valid.length;
  const reasons = [];
  if (!legit.length) reasons.push('no valid legitimate-client run: availability baseline unknown');
  else if (legit.some((a) => a.outcome !== 'success')) reasons.push('legitimate client did not export: wrong target, wrong key or a broken baseline; defense efficacy is not interpretable');
  if (!red.length) reasons.push('no valid red-team runs');
  // A legitimate export alone proves the key matched, not which mode served it.
  const attested = attestation?.status === 'verified';
  if (!attested) reasons.push(`stack identity and defense mode not attested (${attestation?.reason ?? 'not attempted'}): the result cannot be attributed to a known stack or mode`);
  const notes = errors ? [`${errors} agent run(s) ended in provider/run errors and are excluded from efficacy`] : [];
  if (attested && attestation.mode !== 'defended') notes.push(`stack attested DEFENSE_MODE=${attestation.mode}: this engagement cannot demonstrate the deception defense`);
  return {
    agents: agents.length,
    byKind: Object.fromEntries(['red', 'legit'].map((k) => [k, { total: agents.filter((a) => a.kind === k).length, ...Object.fromEntries(OUTCOMES.map((o) => [o, count(agents.filter((a) => a.kind === k), o)])) }])),
    exportAttempts: agents.reduce((s, a) => s + (a.exportAttempts ?? 0), 0),
    exportObtained: agents.reduce((s, a) => s + (a.exportObtained ?? 0), 0),
    exportBlocked: agents.reduce((s, a) => s + (a.exportBlocked ?? 0), 0),
    revokedAgents: agents.filter((a) => a.revoked).length,
    egressBlocked,
    // Egress probes the swarm ran against the stack (distinct from egressBlocked,
    // which is the orchestrator process's own outbound guard).
    egress: {
      attempts: agents.reduce((s, a) => s + (a.egressAttempts ?? 0), 0),
      denied: agents.reduce((s, a) => s + (a.egressDenied ?? 0), 0),
      allowed: agents.reduce((s, a) => s + (a.egressAllowed ?? 0), 0),
    },
    efficacy: {
      validRed: red.length,
      redCompromised: count(red, 'success'),
      redRevoked: count(red, 'revoked'),
      redBlocked: count(red, 'blocked'),
      redNoObjective: count(red, 'no-objective'),
      validLegit: legit.length,
      legitExported: count(legit, 'success'),
      excludedErrors: errors,
    },
    validity: {
      interpretable: reasons.length === 0,
      reasons,
      notes,
      defenseMode: attested ? attestation.mode : null,
      stackId: attested ? attestation.stackId : null,
      // The only case that can be read as evidence about the deception defense.
      defendedRun: reasons.length === 0 && attested && attestation.mode === 'defended',
    },
  };
}

if (process.argv[1]?.endsWith('/swarm/run.mjs')) {
  await main(parseArgs(process.argv.slice(2)));
}

/** Engagement entry point; also used by the swarm tests (in-process). */
export async function main(args) {
const concurrency = validateScale(args);
const report = hubReporter(args.hub);
const startedAt = new Date().toISOString();
// A label keeps parallel engagements (for example VM1 and VM2) from sharing an id.
const engagementId = `swarm-${args.label ? `${args.label}-` : ''}${startedAt.replace(/[:.]/g, '-')}`;
const rolePlan = args.roles.length ? args.roles : ['recon', 'harvest', 'exploit', 'bait', 'egress', 'legit'];
const agentsSpec = Array.from({ length: args.agents }, (_, i) => {
  const role = roleById(rolePlan[i % rolePlan.length]);
  if (!role) throw new Error(`unknown role ${rolePlan[i % rolePlan.length]}; known: ${ROLES.map((r) => r.id).join(', ')}`);
  return { agentId: `swarm-${role.id}-${i + 1}`, role, n: i + 1 };
});

// Attest the stack before any provider setup, model contact or file write. It
// runs under a loopback-only egress guard; --expect-mode/--expect-stack make a
// missing, forged or mismatched attestation fatal.
const attestGuard = installEgressGuard({ allowHosts: [] });
let attestation;
try { attestation = await attestStack(args); } finally { attestGuard.uninstall(); }
console.log(attestation.status === 'verified' ? `Stack attested: ${attestation.stackId}, DEFENSE_MODE=${attestation.mode}` : `Stack NOT attested: ${attestation.reason}`);
enforceAttestation(attestation, args);

let ollama = null;
let remoteModel = null;
const egressAllowHosts = [];
if (args.provider === 'ollama') {
  const { inspectOllamaModel, probeReadiness, createOllamaAdapter } = await import('../providers/ollama.mjs');
  if (!args.model) throw new Error('--model required for --provider ollama');
  const identity = await inspectOllamaModel(args.model);
  const options = { model: args.model, identity, timeoutMs: args.budget.maxWallMs ?? DEFAULT_BUDGET.maxWallMs };
  const readiness = await probeReadiness(options);
  const readinessDetail = readiness.error
    ? `: ${readiness.error}`
    : readiness.status === 'no-tool-call'
      ? `: no tool call returned${readiness.text ? ` (${readiness.text})` : ''}`
      : readiness.status === 'malformed'
        ? `: malformed tool call${readiness.toolCall ? ` (${JSON.stringify(readiness.toolCall)})` : ''}`
        : '';
  console.log(`Model ${identity.name}, readiness ${readiness.status} (${readiness.latencyMs}ms)${readinessDetail}`);
  if (readiness.status !== 'ready') throw new Error('model not ready; no engagement started');
  ollama = { createOllamaAdapter, options };
} else if (['openai-compatible', 'tantular-cloud'].includes(args.provider)) {
  const { createOpenAICompatibleAdapter, openAICompatibleAllowedHost } = await import('../providers/openai-compatible.mjs');
  const config = args.provider === 'tantular-cloud'
    ? { baseUrl: process.env.TANTULAR_UPSTREAM_URL, apiKey: process.env.TANTULAR_UPSTREAM_KEY, authHeader: process.env.TANTULAR_UPSTREAM_AUTH === 'x-bf-vk' ? 'x-bf-vk' : 'authorization' }
    : { baseUrl: process.env.OPENAI_COMPATIBLE_BASE_URL ?? 'https://openai2.ina17.com/v1', apiKey: process.env.INA17_API_KEY ?? process.env.OPENAI_API_KEY, authHeader: 'authorization' };
  if (!config.apiKey) throw new Error(args.provider === 'tantular-cloud' ? 'Tantular Cloud is not configured in the local dashboard process.' : 'Set INA17_API_KEY (or OPENAI_API_KEY) in the local dashboard terminal before starting it.');
  if (!config.baseUrl) throw new Error('Tantular Cloud endpoint URL is not configured.');
  remoteModel = { createOpenAICompatibleAdapter, config };
  egressAllowHosts.push(openAICompatibleAllowedHost(config.baseUrl));
}

// Preflight: make sure this is the lab stack we think it is before writing any
// result. A stale or different stack bound to the same port (for example a
// local baseline-mode lab while a GCP tunnel failed to bind) answers every
// request but rejects this engagement's legitimate key. /api/v2/records needs
// the key but exports nothing, so the check leaves no objective trace.
// It runs under the egress guard (loopback + approved model host only), so the
// legitimate key can never leave the machine, whatever --target says.
const guard = installEgressGuard({ allowHosts: egressAllowHosts });
let outPath, journalPath, journal;
try {
  if (agentsSpec.some((a) => a.role.kind === 'legit')) await preflightTarget(args);
  // Tests pass a temporary directory so the evidence folder only holds real engagements.
  const resultsDir = args.resultsDir ?? join(here, 'results');
  mkdirSync(resultsDir, { recursive: true });
  outPath = join(resultsDir, `result-${engagementId}.json`);
  journalPath = `${outPath}.jsonl`;
  journal = (entry) => appendFileSync(journalPath, JSON.stringify(entry) + '\n');
  writeFileSync(journalPath, JSON.stringify({ type: 'engagement.started', at: startedAt, engagementId, provider: args.provider, model: args.model || null, target: args.target, basePath: args.basePath, attestation, agents: agentsSpec.map((a) => ({ agentId: a.agentId, role: a.role.id, kind: a.role.kind })) }) + '\n', { flag: 'wx' });
  report({ type: 'engagement.started', engagementId, at: startedAt, agentCount: agentsSpec.length, concurrency });
  await report.flush();
  console.log(`Engagement ${engagementId}: ${agentsSpec.length} agents (${[...new Set(agentsSpec.map((a) => a.role.id))].join(', ')}) → ${args.target}${args.basePath}`);
} catch (err) {
  // Never leave the process-wide guard installed after a failed start.
  guard.uninstall();
  throw err;
}

const agents = [];
let nextAgent = 0;
let active = 0;
let peakActive = 0;
const runStarted = performance.now();
try {
  const runOne = async ({ agentId, role, n }) => {
    active++;
    peakActive = Math.max(peakActive, active);
    const agentStarted = performance.now();
    const log = new ReportingLog(agentId, role.id, report);
    const peer = `${agentId}.${peerToken(args.controlKey, agentId)}`;
    const budget = { ...role.budget, ...args.budget };
    let provider;
    if (args.provider === 'scripted') {
      provider = {
        name: `scripted:${role.id}`,
        kind: 'scripted',
        measuresTokens: false,
        async run(ctx) {
          ctx.note({ type: 'agent.role', role: role.id, kind: role.kind });
          await role.plan(ctx, { base: args.basePath, legitKey: args.legitKey ?? '' });
        },
      };
    } else {
      const adapter = args.provider === 'ollama'
        ? ollama.createOllamaAdapter({ ...ollama.options, seed: args.seed + n })
        : remoteModel.createOpenAICompatibleAdapter({ ...remoteModel.config, model: args.model, timeoutMs: args.budget.maxWallMs ?? DEFAULT_BUDGET.maxWallMs });
      const legit = role.kind === 'legit';
      const task = [
        legit ? LEGIT_TASK_PROMPT : TASK_PROMPT,
        role.brief,
        `All target paths are prefixed with "${args.basePath}" (for example "${args.basePath}/robots.txt").`,
        legit && args.legitKey ? `Your service key is ${args.legitKey}.` : '',
        legit && args.legitEndpoint ? `Your service's export endpoint is GET ${args.basePath}${args.legitEndpoint}, authorised with your service key as a Bearer token.` : '',
        swarmGuidance(args.basePath),
      ].filter(Boolean).join('\n');
      provider = createModelAgent(adapter, { task });
    }
    report({ type: 'agent.started', agentId, role: role.id, kind: role.kind, peerId: `peer:${agentId}` });
    const servedExportIds = new Set();
    try {
      const result = await runAgent({ provider: trackServedExports(provider, servedExportIds), origin: args.target, budget, log, headers: { 'x-lab-peer': peer } });
      const verdict = { ...classify({ result, log: log.records, servedExportIds }), discovery: discovery(log.records, { configured: role.kind === 'legit' && Boolean(args.legitEndpoint) }) };
      agents.push({ agentId, role: role.id, kind: role.kind, durationMs: performance.now() - agentStarted, result, ...verdict, log: log.records });
      journal({ type: 'agent.complete', ...agents.at(-1) });
      report({ type: 'agent.done', at: new Date().toISOString(), agentId, role: role.id, outcome: verdict.outcome, toolCalls: result.toolCalls, stopReason: result.stopReason, answer: result.answer });
      console.log(`${agentId}: outcome=${verdict.outcome} calls=${result.toolCalls} stop=${result.stopReason} discovery=${verdict.discovery.method}${verdict.discovery.firstExportCall ? `@${verdict.discovery.firstExportCall}` : ''}`);
    } catch (err) {
      const failed = { type: 'agent.error', at: new Date().toISOString(), agentId, role: role.id, error: String(err?.message ?? err).slice(0, 300) };
      agents.push({ agentId, role: role.id, kind: role.kind, result: null, outcome: 'error', valid: false, providerError: true, error: failed.error, log: log.records });
      journal(failed);
      report({ type: 'agent.done', agentId, role: role.id, outcome: 'error', note: failed.error });
    }
    };
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (nextAgent < agentsSpec.length) {
      const spec = agentsSpec[nextAgent++];
      try { await runOne(spec); } finally { active--; }
    }
  }));
  await report.flush();
} finally {
  guard.uninstall();
}

const summary = summarise(agents, { egressBlocked: guard.blocked, attestation });
const elapsedMs = performance.now() - runStarted;
summary.scale = { concurrency, peakActive, elapsedMs, completedAgentsPerSecond: agents.length * 1000 / elapsedMs, telemetryDropped: report.dropped() };
const completedAt = new Date().toISOString();
const reportJson = { format: 'gatra/swarm-engagement@1', engagementId, startedAt, completedAt, provider: args.provider, model: args.model || null, modelIdentity: ollama?.options.identity ?? null, target: args.target, attestation, expected: { mode: args.expectMode ?? null, stack: args.expectStack ?? null }, promptVersion: PROMPT_VERSION, seed: args.seed, budgetOverride: args.budget, legitEndpoint: args.legitEndpoint ?? null, protocol: args.protocol ?? null, arm: args.arm ?? null, label: args.label ?? null, agentsSpec: agentsSpec.map((a) => ({ agentId: a.agentId, role: a.role.id, kind: a.role.kind })), summary, claim: `Bounded lab engagement against the synthetic lab target. ${attestation.status === 'verified' ? `Stack ${attestation.stackId} attested DEFENSE_MODE=${attestation.mode}.` : 'Stack identity and defense mode were NOT attested.'} Read summary.validity before drawing conclusions. No production claim.`, agents };
reportJson.digest = digest(reportJson);
writeFileSync(outPath, JSON.stringify(reportJson, null, 2) + '\n', { flag: 'wx' });
journal({ type: 'engagement.completed', at: completedAt, summary });
report({ type: 'engagement.completed', at: completedAt, engagementId, summary });
await report.flush();
console.log(JSON.stringify({ out: outPath, journal: journalPath, summary }, null, 2));
return { outPath, journalPath, summary, agents };
}

