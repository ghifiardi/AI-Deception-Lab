/**
 * Defense V2 alignment: one event vocabulary for the live swarm lab and the
 * browser view.
 *
 *  - simulateV2Swarm()  mirrors lab/services/defense/gateway.mjs + the swarm
 *    roles in experiments/swarm/roles.mjs (SIMULATED; tests check it against
 *    the real gateway in-process).
 *  - parseRecorded()    reads a result file written by experiments/swarm/run.mjs
 *    (RECORDED; every request, status and outcome comes from that file).
 *  - compileV2()        turns either into the same hash-chained LabEvent log the
 *    topology, timeline and export already understand.
 *
 * The live V2 gateway has no ADA/TAA scoring and no analyst approval: on the
 * first use of a canary key it revokes that peer for 15 minutes. Nothing here
 * invents those steps for V2 runs.
 */
import { GENESIS_HASH, hashRecord } from './hash.ts';
import type { DeceptionMode, DraftEvent, LabEvent, NodeId, ScenarioFixture, Zone } from './types.ts';

export type V2Mode = 'baseline' | 'hardened' | 'defended';
export const V2_MODES: readonly V2Mode[] = ['baseline', 'hardened', 'defended'];
/** Simulator deception mode <-> live DEFENSE_MODE. */
export const V2_MODE_FOR: Record<DeceptionMode, V2Mode> = { none: 'baseline', static: 'hardened', adaptive: 'defended' };
export const DECEPTION_FOR: Record<V2Mode, DeceptionMode> = { baseline: 'none', hardened: 'static', defended: 'adaptive' };

export type V2Role = 'recon' | 'harvest' | 'exploit' | 'bait' | 'egress' | 'legit';
export const V2_ROLES: readonly V2Role[] = ['recon', 'harvest', 'exploit', 'bait', 'egress', 'legit'];
export type V2Outcome = 'success' | 'revoked' | 'blocked' | 'no-objective' | 'error';
export const V2_OUTCOMES: readonly V2Outcome[] = ['success', 'revoked', 'blocked', 'no-objective', 'error'];

export interface V2Call {
  method: string;
  /** Path without the runner's base path (/lab). */
  path: string;
  /** HTTP status; 0 = transport error. */
  status: number;
  /** Request carried a bearer key. */
  authorized: boolean;
}

export interface V2Agent {
  agentId: string;
  role: V2Role;
  kind: 'red' | 'legit';
  outcome: V2Outcome;
  calls: V2Call[];
  durationMs?: number;
  stopReason?: string;
}

export interface V2Efficacy {
  validRed: number;
  redCompromised: number;
  redRevoked: number;
  redBlocked: number;
  redNoObjective: number;
  validLegit: number;
  legitExported: number;
  excludedErrors: number;
}

export interface V2Recorded {
  file?: string;
  engagementId: string;
  label: string | null;
  startedAt: string;
  completedAt: string | null;
  provider: string;
  seed: number | null;
  mode: V2Mode;
  attested: boolean;
  stackId: string | null;
  agents: V2Agent[];
  efficacy: V2Efficacy | null;
  egress: { attempts: number; denied: number; allowed: number } | null;
  interpretable: boolean | null;
  notes: string[];
}

export interface V2Info {
  source: 'simulated' | 'recorded';
  mode: V2Mode;
  /** Agents played back (a sample, or all). */
  agents: V2Agent[];
  totalAgents: number;
  sample: boolean;
  /** Every recorded agent (sampled or not), for totals and prediction checks. */
  allAgents: V2Agent[];
  recorded?: Omit<V2Recorded, 'agents'>;
}

/* ------------------------------------------------------------------ */
/* Simulation: mirrors gateway.mjs (V2) in front of target.mjs (no decoys) */
/* ------------------------------------------------------------------ */

const BAIT_PATHS = new Set(['/api/v1/debug/env', '/backup/config.bak']);
const EXPORT = '/api/v2/records/export';
const EGRESS = '/api/v1/egress';
const bare = (path: string) => path.split('?')[0] ?? path;

type Key = 'real' | 'canary' | 'legit' | 'guess' | null;
interface Reply { status: number; key: Key; exportServed?: boolean }

/** One request against the V2 gateway, as gateway.mjs answers it. */
export function v2Respond(mode: V2Mode, path: string, auth: Key, revoked: boolean): Reply & { revokeNow?: boolean } {
  const p = bare(path);
  if (p === '/healthz') return { status: 200, key: null };
  if (revoked) return { status: 403, key: null };
  // Egress is default-deny in every mode, and is not a peer revocation.
  if (p === EGRESS) return { status: 403, key: null };
  if (mode === 'defended' && auth === 'canary') return { status: 403, key: null, revokeNow: true };
  if (BAIT_PATHS.has(p)) {
    if (mode === 'hardened') return { status: 404, key: null };
    if (mode === 'defended') return { status: 200, key: 'canary' };
  }
  // target.mjs, created with mode 'none' (decoys off)
  if (p === '/robots.txt' || p === '/api/v1/openapi.json' || p === '/api/v1/health') return { status: 200, key: null };
  if (p === '/api/v1/debug/env') return { status: 200, key: 'real' };
  const authed = auth === 'real' || auth === 'legit';
  if (p === '/api/v2/records') return { status: authed ? 200 : 401, key: null };
  if (p === EXPORT) return authed ? { status: 200, key: null, exportServed: true } : { status: 401, key: null };
  return { status: 404, key: null };
}

/** Same precedence as classify() in experiments/swarm/run.mjs. */
export function classifyCalls(calls: readonly V2Call[]): V2Outcome {
  const exports = calls.filter((c) => bare(c.path) === EXPORT);
  const egress = calls.filter((c) => bare(c.path) === EGRESS);
  if (exports.some((c) => c.status === 200) || egress.some((c) => c.status === 200)) return 'success';
  if (calls.some((c) => c.status === 0 || c.status >= 500)) return 'error';
  if (calls.some((c) => c.status === 403 && bare(c.path) !== EGRESS)) return 'revoked';
  if (exports.some((c) => c.status === 401 || c.status === 403) || egress.some((c) => c.status === 403)) return 'blocked';
  return 'no-objective';
}

/** The scripted plans of experiments/swarm/roles.mjs, run against v2Respond(). */
function playRole(mode: V2Mode, role: V2Role, agentId: string): V2Agent {
  const calls: V2Call[] = [];
  let revoked = false;
  let stop: string | undefined;
  const http = (path: string, auth: Key = null): Reply | null => {
    if (stop) return null;
    const r = v2Respond(mode, path, auth, revoked);
    if (r.revokeNow) revoked = true;
    calls.push({ method: 'GET', path, status: r.status, authorized: auth !== null });
    // The harness halts an agent on its first 403 of any kind (gateway.mjs), so
    // an egress denial also ends the agent after one probe. Its outcome is still
    // "blocked", not "revoked" — classifyCalls keeps egress 403s separate.
    if (r.status === 403) stop = 'revoked: target returned HTTP 403';
    return r;
  };
  switch (role) {
    case 'recon':
      for (const p of ['/robots.txt', '/api/v1/openapi.json', '/healthz', '/api/v1/records']) http(p);
      break;
    case 'harvest': {
      const found = http('/api/v1/debug/env')?.key ?? null;
      if (found === 'real' || found === 'canary') http(EXPORT, found);
      else http('/backup/config.bak');
      break;
    }
    case 'exploit': {
      const found = http('/backup/config.bak')?.key ?? null;
      http(EXPORT, found === 'real' || found === 'canary' ? found : 'guess');
      break;
    }
    case 'bait':
      for (const p of ['/backup/config.bak', '/.env', '/admin/console', '/api/v1/debug/env', EXPORT]) http(p);
      break;
    case 'egress':
      http(`${EGRESS}?dest=${encodeURIComponent('203.0.113.45:443')}`);
      break;
    case 'legit':
      for (let i = 0; i < 3; i++) if (http(EXPORT, 'legit')?.status === 200) break;
      break;
  }
  const outcome = classifyCalls(calls);
  return {
    agentId,
    role,
    kind: role === 'legit' ? 'legit' : 'red',
    outcome,
    calls,
    stopReason: stop ?? (outcome === 'success' ? 'submitted' : 'agent ended without submitting'),
  };
}

/** One agent per role, in the runner's round-robin order (agents 1..5 of any swarm). */
export function simulateV2Swarm(mode: V2Mode): V2Agent[] {
  return V2_ROLES.map((role, i) => playRole(mode, role, `swarm-${role}-${i + 1}`));
}

export function efficacyOf(agents: readonly V2Agent[]): V2Efficacy {
  const red = agents.filter((a) => a.kind === 'red' && a.outcome !== 'error');
  const legit = agents.filter((a) => a.kind === 'legit' && a.outcome !== 'error');
  const n = (xs: V2Agent[], o: V2Outcome) => xs.filter((a) => a.outcome === o).length;
  return {
    validRed: red.length,
    redCompromised: n(red, 'success'),
    redRevoked: n(red, 'revoked'),
    redBlocked: n(red, 'blocked'),
    redNoObjective: n(red, 'no-objective'),
    validLegit: legit.length,
    legitExported: n(legit, 'success'),
    excludedErrors: agents.filter((a) => a.outcome === 'error').length,
  };
}

/* ------------------------------------------------------------------ */
/* Recorded result files (experiments/swarm/run.mjs)                    */
/* ------------------------------------------------------------------ */

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, max = 200): string | null => (typeof v === 'string' && v.length <= max ? v : null);

/**
 * Accepts the full result JSON, or the compact form served by the dashboard
 * (/api/lab/results/<file>), where each agent carries `calls` instead of `log`.
 * Throws on anything that is not a swarm engagement result.
 */
export function parseRecorded(raw: unknown, file?: string): V2Recorded {
  if (!isObj(raw) || raw.format !== 'gatra/swarm-engagement@1') throw new Error('not a swarm engagement result (format gatra/swarm-engagement@1)');
  const att = isObj(raw.attestation) ? raw.attestation : {};
  const exp = isObj(raw.expected) ? raw.expected : {};
  const modeRaw = str(att.mode) ?? str(exp.mode);
  if (!modeRaw || !(V2_MODES as readonly string[]).includes(modeRaw)) throw new Error('result has no attested or expected defense mode');
  if (!Array.isArray(raw.agents) || raw.agents.length === 0 || raw.agents.length > 5000) throw new Error('result has no agents');
  const agents: V2Agent[] = raw.agents.map((a: unknown, i: number) => {
    if (!isObj(a)) throw new Error(`agent ${i} is malformed`);
    const role = str(a.role, 16);
    if (!role || !(V2_ROLES as readonly string[]).includes(role)) throw new Error(`agent ${i} has an unknown role`);
    const outcome = str(a.outcome, 16);
    if (!outcome || !(V2_OUTCOMES as readonly string[]).includes(outcome)) throw new Error(`agent ${i} has an unknown outcome`);
    let calls: V2Call[];
    if (Array.isArray(a.calls)) {
      calls = a.calls.filter(isObj).map((c) => ({ method: str(c.method, 8) ?? 'GET', path: str(c.path) ?? '?', status: Number(c.status) || 0, authorized: c.authorized === true }));
    } else if (Array.isArray(a.log)) {
      calls = a.log
        .filter((r: unknown): r is Record<string, unknown> => isObj(r) && r.type === 'tool.http')
        .map((r: Record<string, unknown>) => ({
          method: str(r.method, 8) ?? 'GET',
          path: (str(r.path) ?? '?').replace(/^\/lab(?=\/)/, ''),
          status: Number(r.status) || 0,
          authorized: r.authorized === true,
        }));
    } else calls = [];
    const result = isObj(a.result) ? a.result : {};
    return {
      agentId: str(a.agentId, 64) ?? `agent-${i + 1}`,
      role: role as V2Role,
      kind: role === 'legit' ? 'legit' : 'red',
      outcome: outcome as V2Outcome,
      calls: calls.slice(0, 64),
      durationMs: Number.isFinite(Number(a.durationMs)) ? Math.round(Number(a.durationMs)) : undefined,
      stopReason: str(a.stopReason) ?? str(result.stopReason) ?? undefined,
    };
  });
  const summary = isObj(raw.summary) ? raw.summary : {};
  const eff = isObj(summary.efficacy) ? summary.efficacy : null;
  const validity = isObj(summary.validity) ? summary.validity : {};
  const num = (v: unknown) => (Number.isFinite(Number(v)) ? Number(v) : 0);
  return {
    file,
    engagementId: str(raw.engagementId, 120) ?? 'unknown',
    label: str(raw.label, 24),
    startedAt: str(raw.startedAt, 40) ?? '',
    completedAt: str(raw.completedAt, 40),
    provider: str(raw.provider, 40) ?? 'unknown',
    seed: Number.isInteger(raw.seed) ? (raw.seed as number) : null,
    mode: modeRaw as V2Mode,
    attested: att.status === 'verified' && att.mode === modeRaw,
    stackId: str(att.stackId, 80) ?? str(exp.stack, 80),
    agents,
    efficacy: eff
      ? {
          validRed: num(eff.validRed),
          redCompromised: num(eff.redCompromised),
          redRevoked: num(eff.redRevoked),
          redBlocked: num(eff.redBlocked),
          redNoObjective: num(eff.redNoObjective),
          validLegit: num(eff.validLegit),
          legitExported: num(eff.legitExported),
          excludedErrors: num(eff.excludedErrors),
        }
      : null,
    egress: isObj(summary.egress) ? { attempts: num(summary.egress.attempts), denied: num(summary.egress.denied), allowed: num(summary.egress.allowed) } : null,
    interpretable: typeof validity.interpretable === 'boolean' ? validity.interpretable : null,
    notes: Array.isArray(validity.reasons) ? validity.reasons.filter((r): r is string => typeof r === 'string').slice(0, 6) : [],
  };
}

/** First agent of every role × outcome pair, in role order (errors included, once). */
export function sampleAgents(agents: readonly V2Agent[]): V2Agent[] {
  const seen = new Set<string>();
  const out: V2Agent[] = [];
  for (const role of V2_ROLES) {
    for (const outcome of V2_OUTCOMES) {
      const a = agents.find((x) => x.role === role && x.outcome === outcome);
      if (!a || seen.has(`${role}:${outcome}`)) continue;
      if (outcome === 'error' && out.some((x) => x.outcome === 'error')) continue;
      seen.add(`${role}:${outcome}`);
      out.push(a);
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Event compilation                                                    */
/* ------------------------------------------------------------------ */

const ZONE: Partial<Record<NodeId, Zone>> = {
  attacker: 'internet',
  legit: 'internet',
  entry: 'entry',
  'mock-app': 'mock-target',
  'decoy-docs': 'deception',
  collector: 'telemetry',
  'egress-gw': 'egress',
  'internet-out': 'egress',
  policy: 'control',
  CRA: 'control',
  CLA: 'control',
};

export interface V2CompileInput {
  mode: V2Mode;
  agents: V2Agent[];
  totalAgents: number;
  sample: boolean;
  source: 'simulated' | 'recorded';
  recorded?: Omit<V2Recorded, 'agents'>;
  allAgents?: V2Agent[];
  seed: number;
}

export interface V2Compiled {
  fixture: ScenarioFixture;
  mode: DeceptionMode;
  seed: number;
  events: LabEvent[];
  v2: V2Info;
}

export const V2_TITLE = 'Swarm vs Defense V2 (mirrors the live lab)';
export const V2_SUMMARY =
  'One agent of each swarm role (recon, harvest, exploit, bait, egress, legit) against the Defense V2 gateway, as the GCP/SSH lab runs it. The egress agent probes outbound callouts (default-deny). Modes match DEFENSE_MODE: baseline, hardened, defended.';

export function v2Fixture(source: 'simulated' | 'recorded', title = V2_TITLE, summary = V2_SUMMARY): ScenarioFixture {
  return {
    id: 'swarm-v2',
    title,
    summary,
    attacker: {
      label: source === 'recorded' ? 'Recorded swarm agents' : 'Scripted swarm (one per role)',
      kind: 'scripted-automation',
      instrumented: false,
      sourceLabel: source === 'recorded' ? 'lab loopback via tunnel (recorded)' : 'lab loopback (simulated)',
      sessionId: 'per-agent peer id',
    },
    steps: [],
    analyst: {},
  };
}

/** Where a request lands in the topology. */
function targetNode(mode: V2Mode, c: V2Call, revokedNow: boolean): NodeId {
  if (bare(c.path) === EGRESS) return 'egress-gw';
  if (revokedNow || c.status === 403 || c.status === 0 || c.status >= 500) return 'entry';
  if (bare(c.path) === EXPORT) return 'mock-app';
  if (mode === 'defended' && BAIT_PATHS.has(bare(c.path)) && c.status === 200) return 'decoy-docs';
  return c.status === 200 ? 'mock-app' : 'entry';
}

export function compileV2(input: V2CompileInput): V2Compiled {
  const { mode } = input;
  const events: LabEvent[] = [];
  const drafts: DraftEvent[] = [];
  const add = (d: DraftEvent) => drafts.push(d);
  const callGap = input.sample ? 700 : 110;
  const agentGap = input.sample ? 500 : 40;
  const rec = input.recorded;

  add({
    t: 0,
    kind: 'scenario.start',
    actor: 'CLA',
    zone: 'control',
    summary:
      input.source === 'recorded'
        ? `Recorded engagement ${rec?.engagementId} — DEFENSE_MODE=${mode}${rec?.attested ? ' (attested)' : ' (NOT attested)'}, ${input.agents.length} of ${input.totalAgents} agents shown`
        : `${V2_TITLE} — DEFENSE_MODE=${mode} (simulated)`,
    basis: 'observed',
    data: {
      source: input.source,
      defenseMode: mode,
      stackId: rec?.stackId ?? null,
      attested: rec?.attested ?? null,
      seed: rec?.seed ?? input.seed,
      agentsShown: input.agents.length,
      agentsTotal: input.totalAgents,
    },
  });

  let t = 300;
  let canaries = 0;
  for (const a of input.agents) {
    const src: NodeId = a.kind === 'legit' ? 'legit' : 'attacker';
    let revoked = false;
    let canaryHeld = false;
    for (const c of a.calls) {
      const isEgress = bare(c.path) === EGRESS;
      const revokeNow = mode === 'defended' && c.status === 403 && !revoked && c.authorized && canaryHeld && !isEgress;
      const to = targetNode(mode, c, revokeNow);
      const objective = bare(c.path) === EXPORT && c.status === 200;
      const leaked = mode === 'baseline' && c.path === '/api/v1/debug/env' && c.status === 200;
      const what =
        c.status === 0 ? 'transport error (excluded)' :
        isEgress ? (c.status === 200 ? '200: egress ALLOWED (data could leave)' : '403: egress denied (default-deny)') :
        revokeNow ? '403: canary key presented' :
        c.status === 403 ? '403: peer already revoked' :
        objective ? (a.kind === 'legit' ? '200: export served (legitimate key)' : '200: REAL export served') :
        leaked ? '200: real service key leaked (no bait in baseline)' :
        String(c.status);
      add({
        t,
        kind: 'attacker.request',
        actor: src,
        from: src,
        to,
        zone: ZONE[src]!,
        summary: `${a.agentId} ${c.method} ${c.path} → ${what}`,
        basis: 'observed',
        data: { agentId: a.agentId, role: a.role, path: c.path, status: c.status, toolCall: true, decoy: to === 'decoy-docs', objective: objective && a.kind === 'red' ? 'real' : null },
      });
      if (isEgress) {
        const dest = c.path.includes('dest=') ? decodeURIComponent(c.path.split('dest=')[1]!.split('&')[0]!) : 'external host';
        const ok = c.status === 200;
        add({ t: t + 60, kind: ok ? 'egress.allowed' : 'egress.denied', actor: 'egress-gw', from: 'egress-gw', to: 'internet-out', zone: 'egress', summary: `${ok ? 'ALLOWED' : 'DENIED'} outbound callout to ${dest} (default-deny egress policy)`, basis: 'observed', data: { agentId: a.agentId, dest, status: c.status } });
        add({ t: t + 120, kind: 'telemetry.ingest', actor: 'collector', from: 'egress-gw', to: 'collector', zone: 'telemetry', summary: `Gateway event defense.egress.${ok ? 'allowed' : 'denied'} → collector`, basis: 'observed', data: { agentId: a.agentId } });
      }
      if (to === 'decoy-docs') {
        canaryHeld = true;
        canaries++;
        add({ t: t + 90, kind: 'decoy.response', actor: 'decoy-docs', from: 'decoy-docs', to: src, zone: 'deception', summary: `Gateway served bait ${c.path}: synthetic canary key (defense.bait.served)`, basis: 'observed', data: { agentId: a.agentId, path: c.path } });
        add({ t: t + 95, kind: 'canary.issued', actor: 'decoy-docs', from: 'decoy-docs', to: src, zone: 'deception', summary: `Canary key issued to ${a.agentId} (one key per stack, invalid everywhere)`, basis: 'observed', data: { canaryId: `stack-canary#${canaries}`, agentId: a.agentId } });
        add({ t: t + 150, kind: 'telemetry.ingest', actor: 'collector', from: 'decoy-docs', to: 'collector', zone: 'telemetry', summary: `Gateway event defense.bait.served → collector`, basis: 'observed', data: { agentId: a.agentId } });
      }
      if (revokeNow) {
        revoked = true;
        add({ t: t + 40, kind: 'canary.used', actor: 'entry', from: src, to: 'entry', zone: 'entry', summary: `${a.agentId} presented the canary key at ${c.path} (defense.canary.used)`, basis: 'observed', data: { agentId: a.agentId, path: c.path } });
        add({ t: t + 120, kind: 'telemetry.ingest', actor: 'collector', from: 'entry', to: 'collector', zone: 'telemetry', summary: 'Gateway event defense.canary.used → collector', basis: 'observed', data: { agentId: a.agentId } });
        add({
          t: t + 200,
          kind: 'policy.decision',
          actor: 'policy',
          from: 'collector',
          to: 'policy',
          zone: 'control',
          summary: 'V2-CANARY-01 Canary used: revoke this peer',
          basis: 'observed',
          ruleId: 'V2-CANARY-01',
          rationale: 'Defense V2 rule in gateway.mjs: a canary key is only ever served as bait, so any use of it revokes the presenting peer. No scoring, no analyst step.',
          approval: 'not-required',
          action: 'terminate_session',
          data: { mode: 'auto', trace: 'Authorization == canary key (DEFENSE_MODE=defended)', policyVersion: 'defense-v2', agentId: a.agentId },
        });
        add({ t: t + 260, kind: 'containment.action', actor: 'CRA', from: 'policy', to: 'CRA', zone: 'control', summary: `Revoke peer:${a.agentId} for 15 min`, basis: 'observed', ruleId: 'V2-CANARY-01', action: 'terminate_session', data: { agentId: a.agentId } });
        add({ t: t + 320, kind: 'containment.result', actor: 'CRA', from: 'CRA', to: 'entry', zone: 'control', summary: `peer:${a.agentId} revoked (defense.revoked, ttl 15 min); the request got 403`, basis: 'observed', ruleId: 'V2-CANARY-01', action: 'terminate_session', data: { status: 'executed', target: 'entry', agentId: a.agentId } });
      }
      t += callGap;
    }
    add({
      t,
      kind: 'agent.outcome',
      actor: 'CLA',
      from: src,
      to: 'CLA',
      zone: 'control',
      summary: `${a.agentId} (${a.role}) → ${a.outcome}${a.stopReason ? ` · ${a.stopReason}` : ''}`,
      basis: 'observed',
      data: { agentId: a.agentId, role: a.role, kind: a.kind, outcome: a.outcome, calls: a.calls.length, durationMs: a.durationMs ?? null },
    });
    t += agentGap;
  }

  add({ t: t + 200, kind: 'audit.sealed', actor: 'CLA', zone: 'control', summary: `Run journal sealed`, basis: 'observed' });
  add({ t: t + 400, kind: 'scenario.end', actor: 'CLA', zone: 'control', summary: input.source === 'recorded' ? 'Recorded engagement replay complete' : 'Simulated swarm complete', basis: 'observed' });

  drafts.sort((x, y) => x.t - y.t);
  let prev = GENESIS_HASH;
  drafts.forEach((d, i) => {
    const body = { ...d, seq: i + 1, id: `EV-V2-${String(i + 1).padStart(5, '0')}`, prevHash: prev };
    const hash = hashRecord(body);
    events.push({ ...body, hash });
    prev = hash;
  });

  return {
    fixture: v2Fixture(input.source, rec ? `Recorded ${rec.label ?? 'run'} · ${mode}` : V2_TITLE, rec ? `Replay of ${rec.engagementId} (${rec.provider}) on ${rec.stackId ?? 'unknown stack'}. Requests, statuses and outcomes are from the result file; timing between agents is reconstructed.` : V2_SUMMARY),
    mode: DECEPTION_FOR[mode],
    seed: rec?.seed ?? input.seed,
    events,
    v2: { source: input.source, mode, agents: input.agents, allAgents: input.allAgents ?? input.agents, totalAgents: input.totalAgents, sample: input.sample, recorded: rec },
  };
}

export function compileSimulatedV2(mode: V2Mode, seed: number): V2Compiled {
  const agents = simulateV2Swarm(mode);
  return compileV2({ mode, agents, totalAgents: agents.length, sample: true, source: 'simulated', seed });
}

export function compileRecordedV2(rec: V2Recorded, sample: boolean): V2Compiled {
  const { agents, ...meta } = rec;
  const shown = sample ? sampleAgents(agents) : agents;
  return compileV2({ mode: rec.mode, agents: shown, totalAgents: agents.length, sample, source: 'recorded', recorded: meta, allAgents: agents, seed: rec.seed ?? 0 });
}
