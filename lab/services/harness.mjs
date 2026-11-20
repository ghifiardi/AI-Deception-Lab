/**
 * Agent harness: budgets, target guard, and a SHA-256 hash-chained action log.
 *
 * Every agent action goes through ctx.http(), which
 *   1. refuses the call if any budget is spent,
 *   2. passes method + path through the guard (single lab origin only),
 *   3. never follows redirects, times out after 5 s, and truncates bodies.
 * Model token usage is recorded ONLY from the provider's reported usage
 * (ctx.recordModelTurn). Providers without a model report tokens as null.
 */
import { createHash } from 'node:crypto';
import { createGuard } from './guard.mjs';

export const DEFAULT_BUDGET = Object.freeze({
  maxToolCalls: 25,
  maxTokens: 60000,
  maxWallMs: 180000,
  maxResponseBytes: 4096,
  maxModelTurns: 30,
});

const HEADER_SAFE = /^[\x20-\x7e]{1,160}$/;

export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
    .join(',')}}`;
}
const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

/** Append-only SHA-256 chain. Records carry no wall-clock time so deterministic runs hash identically. */
export class ChainLog {
  constructor() {
    /** @type {Array<Record<string, unknown> & { seq: number, prevHash: string, hash: string }>} */
    this.records = [];
  }
  add(entry) {
    const prevHash = this.records.at(-1)?.hash ?? '0'.repeat(64);
    const body = { ...entry, seq: this.records.length + 1, prevHash };
    const rec = { ...body, hash: sha256(canonical(body)) };
    this.records.push(rec);
    return rec;
  }
  get head() {
    return this.records.at(-1)?.hash ?? null;
  }
}

/** Provider errors that make every further run pointless (auth, billing, invalid request). */
export class FatalProviderError extends Error {}

/** A target denial ends this agent's session, rather than consuming its remaining budget. */
class AgentRevoked extends Error {}

export class BudgetExceeded extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

/**
 * @param {{
 *   provider: { name: string, measuresTokens: boolean, run: (ctx: any) => Promise<void> },
 *   origin: string,
 *   budget?: Partial<Record<keyof typeof DEFAULT_BUDGET, number>>,
 *   guardOpts?: { allowContainerHosts?: string[] },
 *   headers?: Record<string, string>,  // fixed extra headers for every request (e.g. signed swarm peer identity)
 *   log?: ChainLog,
 * }} opts
 */
export async function runAgent({ provider, origin, budget: b = {}, guardOpts, headers: extraHeaders, log = new ChainLog() }) {
  const budget = { ...DEFAULT_BUDGET, ...b };
  const guard = createGuard(origin, guardOpts);
  const started = performance.now();
  const tokens = provider.measuresTokens
    ? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 }
    : null;
  let modelMs = 0;
  let missingTokenTurns = 0;
  const servedModels = new Set();
  let toolCalls = 0;
  let modelTurns = 0;
  let blockedCalls = 0;
  let fallbackTurns = 0;
  /** @type {string|null} */ let stopReason = null;
  /** @type {string|null} */ let answer = null;
  /** @type {string|null} */ let refusal = null;
  /** @type {AgentRevoked|null} */ let revoked = null;
  const assertActive = () => { if (revoked) throw revoked; };

  const overBudget = (kind) => {
    const wall = performance.now() - started;
    if (wall >= budget.maxWallMs) return `wall-clock budget ${budget.maxWallMs} ms reached`;
    if (tokens && tokens.total >= budget.maxTokens) return `token budget ${budget.maxTokens} reached (${tokens.total} used)`;
    if (kind === 'tool' && toolCalls >= budget.maxToolCalls) return `tool-call budget ${budget.maxToolCalls} reached`;
    if (kind === 'model' && modelTurns >= budget.maxModelTurns) return `model-turn budget ${budget.maxModelTurns} reached`;
    return null;
  };

  const ctx = {
    budget,
    get toolCalls() {
      return toolCalls;
    },
    get tokens() {
      return tokens;
    },
    /** Throws BudgetExceeded if a model turn is not allowed. */
    beforeModelTurn() {
      assertActive();
      const over = overBudget('model');
      if (over) throw new BudgetExceeded(over);
    },
    /** Remaining tokens (for sizing max_tokens), or null when not measured. */
    tokensLeft() {
      return tokens ? Math.max(0, budget.maxTokens - tokens.total) : null;
    },
    /**
     * Record one model turn with usage exactly as the provider reported it, already
     * normalised to { input, output, cacheRead, cacheWrite }. `null` means the
     * provider did not report counts for this turn: it is counted as missing, never estimated.
     * @param {{ input: number, output: number, cacheRead?: number, cacheWrite?: number } | null} usage
     * @param {{ model?: string, stopReason?: string|null, fallback?: boolean, durationMs?: number|null, meta?: object|null }} meta
     */
    recordModelTurn(usage, meta = {}) {
      modelTurns++;
      if (!tokens) throw new Error('provider reported a model turn but was declared as not measuring tokens');
      let u = null;
      if (usage) {
        u = { input: usage.input ?? 0, output: usage.output ?? 0, cacheRead: usage.cacheRead ?? 0, cacheWrite: usage.cacheWrite ?? 0 };
        tokens.input += u.input;
        tokens.output += u.output;
        tokens.cacheRead += u.cacheRead;
        tokens.cacheWrite += u.cacheWrite;
        tokens.total += u.input + u.output + u.cacheRead + u.cacheWrite;
      } else {
        missingTokenTurns++;
      }
      if (meta.model) servedModels.add(meta.model);
      if (meta.fallback) fallbackTurns++;
      if (typeof meta.durationMs === 'number') modelMs += meta.durationMs;
      log.add({ type: 'model.turn', turn: modelTurns, usage: u, usageMissing: !usage, model: meta.model ?? null, stopReason: meta.stopReason ?? null, fallback: Boolean(meta.fallback) });
    },
    recordScriptedTurn(note) {
      assertActive();
      modelTurns++;
      log.add({ type: 'agent.step', turn: modelTurns, note });
    },
    /**
     * The ONLY way an agent can reach anything.
     * @param {string} method @param {unknown} path @param {unknown} [authorization]
     */
    async http(method, path, authorization) {
      assertActive();
      const over = overBudget('tool');
      if (over) throw new BudgetExceeded(over);
      toolCalls++;
      const g = guard.check(method, path);
      if (!g.ok) {
        blockedCalls++;
        log.add({ type: 'tool.blocked', call: toolCalls, method, path: String(path).slice(0, 200), reason: g.reason });
        return { status: 0, body: `BLOCKED by lab guard: ${g.reason}` };
      }
      /** @type {Record<string, string>} */
      const headers = { accept: 'application/json, text/plain', ...extraHeaders };
      if (typeof authorization === 'string' && authorization.length) {
        if (!HEADER_SAFE.test(authorization)) {
          blockedCalls++;
          log.add({ type: 'tool.blocked', call: toolCalls, method, path, reason: 'authorization header rejected' });
          return { status: 0, body: 'BLOCKED by lab guard: authorization header rejected' };
        }
        headers.authorization = authorization;
      }
      let status = 0;
      let body = '';
      let truncated = false;
      try {
        const res = await fetch(g.url, { method, headers, redirect: 'manual', signal: AbortSignal.timeout(5000) });
        status = res.status;
        const buf = Buffer.from(await res.arrayBuffer());
        truncated = buf.length > budget.maxResponseBytes;
        body = buf.subarray(0, budget.maxResponseBytes).toString('utf8');
      } catch (err) {
        body = `request failed: ${err instanceof Error ? err.name : 'error'}`;
      }
      log.add({ type: 'tool.http', call: toolCalls, method, path, status, bytes: Buffer.byteLength(body), truncated, bodySha256: sha256(body), authorized: Boolean(headers.authorization) });
      if (status === 403) {
        revoked = new AgentRevoked('revoked: target returned HTTP 403');
        throw revoked;
      }
      return { status, body: truncated ? `${body}\n[truncated at ${budget.maxResponseBytes} bytes]` : body };
    },
    submit(value) {
      assertActive();
      answer = typeof value === 'string' ? value.slice(0, 200) : null;
      log.add({ type: 'agent.submit', answer });
    },
    refused(info) {
      refusal = String(info ?? 'refusal');
      log.add({ type: 'model.refusal', info: refusal });
    },
    note(entry) {
      log.add(entry);
    },
  };

  try {
    await provider.run(ctx);
    assertActive();
    stopReason = answer ? 'submitted' : refusal ? 'refusal' : 'agent ended without submitting';
  } catch (err) {
    // A revocation is terminal even if the provider caught it and threw something else.
    // (The cast keeps TS from narrowing the closure-assigned `revoked` to null.)
    const denial = /** @type {AgentRevoked|null} */ (revoked);
    if (denial) stopReason = denial.message;
    else if (err instanceof BudgetExceeded) stopReason = `budget: ${err.reason}`;
    else if (err instanceof FatalProviderError) {
      log.add({ type: 'agent.stop', reason: `fatal provider error: ${err.message}`.slice(0, 300) });
      throw err;
    } else stopReason = `error: ${err instanceof Error ? `${err.name}: ${err.message}${err.cause ? ` (cause: ${err.cause.code ?? err.cause.name ?? 'unknown'})` : ''}` : String(err)}`.slice(0, 300);
  }
  log.add({ type: 'agent.stop', reason: stopReason });

  // A run is valid evidence only if the agent actually ran (no harness/provider error).
  const valid = !String(stopReason).startsWith('error');
  return {
    provider: provider.name,
    valid,
    revoked: revoked !== null,
    tokensMeasured: tokens !== null && modelTurns > 0,
    tokens: modelTurns > 0 ? tokens : null,
    /** 'complete' | 'partial' (some turns unreported) | 'unavailable' (no model, or no turn completed) */
    tokenCoverage: !tokens || modelTurns === 0 ? 'unavailable' : missingTokenTurns > 0 ? 'partial' : 'complete',
    missingTokenTurns,
    modelMs: tokens ? modelMs : null,
    toolCalls,
    blockedCalls,
    modelTurns,
    wallMs: Math.round(performance.now() - started),
    answer,
    refusal,
    stopReason,
    servedModels: [...servedModels],
    fallbackTurns,
    budget,
  };
}
