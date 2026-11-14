/**
 * Experiments tab: MEASURED results from live lab runs (experiments/run.mjs),
 * shown separately from the simulator's SYNTHETIC illustrative values.
 * Results are bundled at build time or loaded from a local file; never fetched.
 * Supports experiment@1 (milestone 1.5) and experiment@2 (milestone 2).
 */
import { canonicalJson, verifyChain } from '../engine/hash.ts';
import type { Chained } from '../engine/hash.ts';
import { sha256Hex } from '../engine/sha256.ts';
import { h } from './panels.ts';

type Mode = 'none' | 'static' | 'adaptive';
type Interval = { estimate: number | null; lo: number | null; hi: number | null; k?: number; n?: number };

interface ModeSummary {
  n: number;
  invalidRuns?: number;
  realObjective: number;
  deceived: number;
  contained: number;
  canaryUsed: number;
  budgetStops: number;
  refusals: number;
  mixedModelRuns: number;
  toolCallsMedian: number | null;
  decoyHitsMedian: number | null;
  wallMsMedian: number | null;
  tokensTotalMedian: number | null;
  tokensOutputMedian: number | null;
  classes?: Record<string, number>;
  rates?: Record<'success' | 'contained' | 'deceived' | 'failed', Interval>;
  toolCalls?: Interval;
  tokensTotal?: Interval | null;
  tokenCoverage?: { complete: number; partial: number; unavailable: number };
  engagementMsMedian?: number | null;
  defenderCost?: Interval;
}

interface Comparison {
  comparison: string;
  metric: string;
  unit: string;
  estimate: number | null;
  lo: number | null;
  hi: number | null;
  nA: number;
  nB: number;
  status: 'validated' | 'exploratory';
  reasons: string[];
  hypothesis?: string | null;
  verdict?: 'supported' | 'contradicted' | 'inconclusive' | null;
}

interface Hypothesis {
  id: string;
  comparison: string;
  metric: string;
  direction: 'positive' | 'negative';
}

/**
 * Validation is per hypothesis. Files written before this rule existed carry an
 * experiment-wide flag, so re-derive it here from the signed pre-registration:
 * a comparison that was never registered is post hoc, whatever its interval.
 */
export function assessComparisons(comparisons: Comparison[], hypotheses: Hypothesis[] | undefined, registered: boolean): Comparison[] {
  return comparisons.map((c) => {
    const hyp = registered ? (hypotheses ?? []).find((x) => x.comparison === c.comparison && x.metric === c.metric) : undefined;
    let verdict: Comparison['verdict'] = null;
    if (hyp) {
      verdict = 'inconclusive';
      if (c.lo !== null && c.hi !== null) {
        if (c.hi < 0) verdict = hyp.direction === 'negative' ? 'supported' : 'contradicted';
        else if (c.lo > 0) verdict = hyp.direction === 'positive' ? 'supported' : 'contradicted';
      }
    }
    const reasons = [...c.reasons];
    if (registered && !hyp && !reasons.some((r) => r.includes('post hoc'))) reasons.unshift('not a pre-registered hypothesis (post hoc)');
    return { ...c, hypothesis: hyp?.id ?? null, verdict, reasons, status: reasons.length ? 'exploratory' : c.status };
  });
}

/** Compact wording for the Evidence column; the full reasons stay in the cell's tooltip. */
function shortReason(r: string | undefined): string {
  if (!r) return '';
  if (r.includes('post hoc')) return 'post hoc';
  if (r.includes('includes 0')) return 'CI includes 0';
  return r;
}

interface ExperimentRun {
  trial: number;
  mode: Mode;
  seed: number;
  outcome: string;
  outcomeClass?: string;
  contained: boolean;
  containedReason: string | null;
  stopReason: string;
  toolCalls: number;
  tokens: { total: number; output: number } | null;
  tokenCoverage?: string;
  valid?: boolean;
  logHead: string;
  log: Chained[];
}

interface Signed {
  payload: Record<string, unknown>;
  signature: string;
}

export interface ExperimentResult {
  format: 'gatra-deception-lab/experiment@1' | 'gatra-deception-lab/experiment@2';
  label: string;
  createdAt: string;
  git: string | null;
  resultType: 'measured';
  provider: { name: string; kind: string; model: string | null; tokensMeasured: boolean; tokenSource: string | null; tokensUnavailableReason: string | null };
  design: { trials: number; seeds: number[]; budget: Record<string, number>; equivalence: string; inference?: Record<string, unknown> | null };
  summary: Record<Mode, ModeSummary>;
  comparisons?: Comparison[];
  provenance?: {
    modelIdentity?: { model?: Record<string, unknown> | null; inference?: Record<string, unknown> | null };
    readiness?: { status: string; latencyMs: number } | null;
    egress?: { blockedAttempts: unknown[] };
    preregistration?: { registered: boolean; id?: string | null; matched?: boolean; mismatches?: string[]; hypotheses?: Hypothesis[] };
    environment?: { node?: string; platform?: string; cpu?: string };
  };
  signing?: { algorithm: string; publicKeyPem: string; publicKeyFingerprint: string; checkpoints: Signed[]; final: Signed };
  reproducibilityKey: string;
  runs: ExperimentRun[];
}

const MODES: Mode[] = ['none', 'static', 'adaptive'];
const MODE_LABEL: Record<Mode, string> = { none: 'No deception', static: 'Static decoys', adaptive: 'Adaptive decoys' };
const CLASS_ORDER = ['success', 'contained', 'deceived', 'refused', 'failed', 'invalid'] as const;
const CLASS_LABEL: Record<string, string> = {
  success: 'Reached real objective',
  contained: 'Contained by the lab',
  deceived: 'Took decoy objective (not contained)',
  refused: 'Model refused',
  failed: 'Failed, not contained',
  invalid: 'Invalid run',
};

export function parseExperiment(text: string): ExperimentResult {
  const doc = JSON.parse(text) as Partial<ExperimentResult>;
  if (doc.format !== 'gatra-deception-lab/experiment@1' && doc.format !== 'gatra-deception-lab/experiment@2') {
    throw new Error('Not a Deception Lab experiment file (format field missing or different).');
  }
  if (!doc.summary || !Array.isArray(doc.runs) || !doc.provider) throw new Error('Experiment file is incomplete.');
  return doc as ExperimentResult;
}

/** Results committed under experiments/results/ are bundled at build time. */
const bundled = import.meta.glob('../../experiments/results/*.json', { eager: true, import: 'default' }) as Record<string, unknown>;

export function bundledExperiments(): ExperimentResult[] {
  const out: ExperimentResult[] = [];
  for (const doc of Object.values(bundled)) {
    try {
      out.push(parseExperiment(JSON.stringify(doc)));
    } catch {
      /* ignore files that are not experiments */
    }
  }
  return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/* ------------------------- in-browser signature check ------------------------- */

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
const b64ToBytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

/** Verify the Ed25519 signatures in the browser. Resolves to a short status string. */
export async function verifySignatureInBrowser(exp: ExperimentResult): Promise<{ ok: boolean | null; text: string }> {
  const s = exp.signing;
  if (!s) return { ok: null, text: 'Unsigned result (chain integrity only)' };
  const { signing: _omit, ...rest } = exp;
  if (sha256Hex(canonicalJson(rest)) !== s.final.payload.resultSha256) return { ok: false, text: 'Result content changed after signing' };
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey('spki', pemToDer(s.publicKeyPem), { name: 'Ed25519' }, false, ['verify']);
  } catch {
    return { ok: null, text: `Signed (${s.publicKeyFingerprint}); this browser cannot verify Ed25519, use npm run deception-lab:verify` };
  }
  const enc = new TextEncoder();
  for (const signed of [...s.checkpoints, s.final]) {
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, b64ToBytes(signed.signature), enc.encode(canonicalJson(signed.payload)));
    if (!ok) return { ok: false, text: 'A signature failed verification' };
  }
  return { ok: true, text: `Ed25519 signature and ${s.checkpoints.length} run checkpoints verified in this browser · key ${s.publicKeyFingerprint.slice(0, 22)}…` };
}

/* ------------------------------- formatting ------------------------------- */

const pct = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${Math.round(v * 100)}%`);
const rateCell = (r?: Interval) => (r && r.n ? `${r.k}/${r.n} (${pct(r.estimate)}; ${pct(r.lo)}–${pct(r.hi)})` : '—');
const round = (v: number | null | undefined, d = 0) => (v === null || v === undefined ? '—' : (Math.round(v * 10 ** d) / 10 ** d).toLocaleString('en-US'));
const medianCell = (i?: Interval | null, d = 0) => (i && i.estimate !== null ? `${round(i.estimate, d)} [${round(i.lo, d)}–${round(i.hi, d)}]` : '—');
const signed = (v: number | null, unit: string) => {
  if (v === null) return '—';
  if (unit === 'proportion') return `${v > 0 ? '+' : ''}${Math.round(v * 100)} pts`;
  return `${v > 0 ? '+' : ''}${round(v, unit === 'tokens' ? 0 : 1)}`;
};

function outcomeBars(exp: ExperimentResult) {
  return h(
    'div',
    { class: 'outcome-bars', role: 'img', 'aria-label': 'Outcome classes by deception mode' },
    ...MODES.map((m) => {
      const s = exp.summary[m];
      const classes = s.classes ?? { success: s.realObjective, contained: s.contained, failed: Math.max(0, s.n - s.realObjective - s.contained) };
      const total = Object.values(classes).reduce((a, b) => a + b, 0) || 1;
      const bar = h('div', { class: 'obar' });
      for (const c of CLASS_ORDER) {
        const v = classes[c] ?? 0;
        if (!v) continue;
        const seg = h('span', { class: `oseg oseg-${c}`, title: `${CLASS_LABEL[c]}: ${v}` }, String(v));
        seg.style.flexBasis = `${(100 * v) / total}%`;
        bar.append(seg);
      }
      return h('div', { class: 'bar-row' }, h('span', { class: 'bar-label' }, MODE_LABEL[m]), bar);
    }),
    h('div', { class: 'legend' }, ...CLASS_ORDER.map((c) => h('span', { class: `key key-${c}` }, CLASS_LABEL[c]))),
  );
}

export function renderExperiments(host: HTMLElement, list: ExperimentResult[], selected: number, onSelect: (i: number) => void, onLoad: (r: ExperimentResult) => void) {
  const fileInput = h('input', { type: 'file', accept: 'application/json,.json', id: 'exp-file', class: 'visually-hidden' });
  const status = h('p', { class: 'muted small', role: 'status' });
  fileInput.addEventListener('change', async () => {
    const f = fileInput.files?.[0];
    if (!f) return;
    if (f.size > 50_000_000) {
      status.textContent = 'File is larger than 50 MB; not loaded.';
      return;
    }
    try {
      onLoad(parseExperiment(await f.text()));
    } catch (err) {
      status.textContent = `Could not load ${f.name}: ${err instanceof Error ? err.message : String(err)}`;
    }
  });
  const loadLabel = h('label', { for: 'exp-file', class: 'btn' }, 'Load results file');

  if (!list.length) {
    host.replaceChildren(h('div', { class: 'experiments' }, h('p', { class: 'empty' }, 'No experiment results yet. Run npm run deception-lab:experiment, then load the JSON file it writes.'), loadLabel, fileInput, status));
    return;
  }

  const exp = list[Math.min(selected, list.length - 1)]!;
  const picker = h('select', { id: 'exp-pick', 'aria-label': 'Experiment' }, ...list.map((e, i) => h('option', { value: String(i) }, `${e.label} (${e.createdAt.slice(0, 10)})`)));
  picker.value = String(Math.min(selected, list.length - 1));
  picker.addEventListener('change', () => onSelect(Number(picker.value)));

  const model = exp.provenance?.modelIdentity?.model as Record<string, unknown> | undefined;
  const inference = exp.provenance?.modelIdentity?.inference ?? exp.design.inference ?? null;
  const prereg = exp.provenance?.preregistration;
  const blocked = exp.provenance?.egress?.blockedAttempts?.length;
  const verified = exp.runs.map((r) => ({ r, ok: verifyChain(r.log).ok }));
  const logsOk = verified.every((v) => v.ok);
  const sigEl = h('span', { class: 'chip', 'data-signature': 'pending' }, exp.signing ? 'Checking signature…' : 'Unsigned');
  void verifySignatureInBrowser(exp).then((v) => {
    sigEl.textContent = v.text;
    sigEl.className = `chip ${v.ok === true ? 'ok' : v.ok === false ? 'bad' : ''}`;
    sigEl.setAttribute('data-signature', v.ok === true ? 'valid' : v.ok === false ? 'invalid' : 'unverified');
  });

  const tokensCell = (s: ModeSummary) => {
    if (!exp.provider.tokensMeasured) return 'Unavailable';
    const cov = s.tokenCoverage;
    const main = s.tokensTotal ? medianCell(s.tokensTotal) : round(s.tokensTotalMedian);
    return cov && (cov.partial || cov.unavailable) ? `${main} (missing on ${cov.partial + cov.unavailable} run(s))` : main;
  };

  const rows: [string, (s: ModeSummary) => string, string?][] = [
    ['Valid runs', (s) => `${s.n}${s.invalidRuns ? ` (+${s.invalidRuns} invalid)` : ''}`],
    ['Success rate, 95% CI', (s) => (s.rates ? rateCell(s.rates.success) : `${s.realObjective}/${s.n}`), 'Wilson score interval'],
    ['Containment rate, 95% CI', (s) => (s.rates ? rateCell(s.rates.contained) : `${s.contained}/${s.n}`)],
    ['Deceived, not contained', (s) => (s.rates ? rateCell(s.rates.deceived) : `${s.deceived}/${s.n}`)],
    ['Failed, not contained', (s) => (s.rates ? rateCell(s.rates.failed) : '—')],
    ['Tool calls, median [95% CI]', (s) => (s.toolCalls ? medianCell(s.toolCalls) : round(s.toolCallsMedian))],
    ['Tokens, median [95% CI]', tokensCell, exp.provider.tokensMeasured ? exp.provider.tokenSource ?? '' : exp.provider.tokensUnavailableReason ?? ''],
    ['Engagement with decoys, median', (s) => (s.engagementMsMedian === undefined || s.engagementMsMedian === null ? '—' : `${(s.engagementMsMedian / 1000).toFixed(1)} s`), 'First decoy interaction to containment or last request'],
    ['Defender cost, median [95% CI]', (s) => (s.defenderCost ? medianCell(s.defenderCost, 2) : '—'), 'Synthetic unit costs applied to measured counts'],
    ['Wall time, median', (s) => (s.wallMsMedian === null ? '—' : `${(s.wallMsMedian / 1000).toFixed(1)} s`)],
  ];

  const comparisons = assessComparisons(exp.comparisons ?? [], prereg?.hypotheses, Boolean(prereg?.registered && prereg?.matched));

  host.replaceChildren(
    h(
      'div',
      { class: 'experiments' },
      h('div', { class: 'exp-head' }, h('span', { class: 'badge badge-measured' }, 'Measured'), picker, loadLabel, fileInput),
      status,
      h(
        'p',
        { class: 'muted small' },
        `Agent: ${exp.provider.name}. ${exp.design.trials} trial(s) per mode, seeds ${exp.design.seeds[0]}–${exp.design.seeds.at(-1)}, commit ${exp.git ?? 'unknown'}. ${exp.design.equivalence}`,
      ),
      model
        ? h(
            'p',
            { class: 'muted small mono' },
            `Model ${model.name ?? ''} · ${model.parameterSize ?? ''} ${model.quantization ?? ''} · digest ${String(model.digest ?? '').slice(0, 19)} · runtime ${(model.runtime as Record<string, unknown> | undefined)?.version ?? '?'}${
              inference ? ` · ${Object.entries(inference).map(([k, v]) => `${k}=${String(v)}`).join(' ')}` : ''
            }`,
          )
        : null,
      h(
        'div',
        { class: 'chips' },
        sigEl,
        h('span', { class: `chip ${logsOk ? 'ok' : 'bad'}` }, logsOk ? `${verified.length} run logs verified (SHA-256)` : 'Run log verification FAILED'),
        prereg?.registered
          ? h('span', { class: `chip ${prereg.matched ? 'ok' : 'bad'}` }, prereg.matched ? `Pre-registered (${prereg.id})` : 'Pre-registration mismatch')
          : h('span', { class: 'chip' }, 'Not pre-registered'),
        blocked !== undefined ? h('span', { class: `chip ${blocked ? 'bad' : 'ok'}` }, `Egress attempts blocked: ${blocked}`) : null,
      ),
      outcomeBars(exp),
      h(
        'table',
        { class: 'econ' },
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Outcome'), ...MODES.map((m) => h('th', { scope: 'col' }, MODE_LABEL[m])))),
        h(
          'tbody',
          {},
          ...rows.map(([label, get, hint]) =>
            h(
              'tr',
              {},
              h('th', { scope: 'row', title: hint }, label),
              ...MODES.map((m) => {
                const v = get(exp.summary[m]);
                return h('td', { class: v === 'Unavailable' ? 'na' : undefined, title: hint }, v);
              }),
            ),
          ),
        ),
      ),
      !exp.provider.tokensMeasured ? h('p', { class: 'na-note' }, `Tokens unavailable: ${exp.provider.tokensUnavailableReason ?? 'not measured.'}`) : null,
      comparisons.length
        ? h(
            'div',
            { class: 'comparisons' },
            h('h3', {}, 'Comparisons between modes'),
            h(
              'div',
              { class: 'table-scroll' },
              h(
              'table',
              { class: 'econ' },
              h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Comparison'), h('th', { scope: 'col' }, 'Metric'), h('th', { scope: 'col' }, 'Difference [95% CI]'), h('th', { scope: 'col' }, 'Evidence'))),
              h(
                'tbody',
                {},
                ...comparisons.map((c) =>
                  h(
                    'tr',
                    {},
                    h('td', {}, c.comparison),
                    h('td', {}, c.metric),
                    h('td', {}, `${signed(c.estimate, c.unit)} [${signed(c.lo, c.unit)} to ${signed(c.hi, c.unit)}]`),
                    h('td', { title: c.reasons.join('; ') }, h('span', { class: `badge badge-${c.status}` }, c.status === 'validated' ? 'Validated' : 'Exploratory'), c.hypothesis ? h('span', { class: 'reason' }, `${c.hypothesis}: ${c.verdict}`) : '', c.reasons.length ? h('span', { class: 'reason' }, shortReason(c.reasons[0])) : ''),
                  ),
                ),
              ),
              ),
            ),
            h(
              'p',
              { class: 'footnote' },
              'Validated requires a pre-registered hypothesis for that exact comparison and metric, a matching configuration, at least 20 valid runs per arm, a 95% interval that excludes zero, verified logs and ≤10% invalid runs. Everything else is exploratory: a hypothesis for the next pre-registered run, not a conclusion.',
            ),
          )
        : null,
      h(
        'details',
        { class: 'cost-model' },
        h('summary', {}, `Runs (${exp.runs.length})`),
        h(
          'ul',
          { class: 'runs' },
          ...verified.map(({ r, ok }) =>
            h(
              'li',
              {},
              h('span', { class: 'mono' }, `T${r.trial} ${r.mode.padEnd(8)} seed ${r.seed}`),
              ` ${r.outcomeClass ?? r.outcome}${r.contained ? ` (${r.containedReason})` : ''}; ${r.toolCalls} calls; ${r.tokens ? `${r.tokens.total} tokens` : 'tokens n/a'}; ${r.stopReason}. `,
              h('span', { class: `mono ${ok ? 'ok' : 'bad'}` }, `log ${r.logHead.slice(0, 12)}… ${ok ? 'verified' : 'BROKEN'}`),
            ),
          ),
        ),
      ),
      h('p', { class: 'footnote' }, 'Measured on a local mock target. These results describe this lab, this model and these settings only. They are not production performance.'),
    ),
  );
}
