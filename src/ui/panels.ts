/**
 * Panels. All DOM is built with textContent (never innerHTML) so fixture or
 * policy strings can never inject markup.
 */
import type { ComparisonRow, RunMetrics } from '../engine/metrics.ts';
import { COST_MODEL } from '../engine/metrics.ts';
import type { PolicyConfig } from '../engine/policy.ts';
import type { CompiledRun } from '../engine/simulator.ts';
import type { DecisionView, ViewState } from '../engine/state.ts';
import type { AnalystDecision, AnalystInput, LabEvent } from '../engine/types.ts';
import { packetClass } from './topology.ts';

type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { class?: string; title?: string; [attr: string]: string | undefined } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined) continue;
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

const fmtT = (ms: number) => `${(ms / 1000).toFixed(2)}s`;

const SESSION_LABEL: Record<ViewState['session'], string> = {
  'not-started': 'Waiting',
  active: 'Active',
  throttled: 'Throttled',
  'workload-contained': 'Contained: workload quarantined',
  terminated: 'Contained',
  'stopped-by-harness': 'Stopped by harness',
  finished: 'Finished, not contained',
};

const APPROVAL_LABEL = {
  'not-required': 'No approval needed',
  pending: 'Awaiting human',
  approved: 'Approved',
  denied: 'Rejected by analyst',
  deferred: 'Analyst keeps observing',
} as const;

/* ------------------------------------------------------------------ */
/* Decision panel                                                       */
/* ------------------------------------------------------------------ */

export interface AnalystUi {
  interactive: boolean;
  inputs: AnalystInput[];
  onDecide: (ruleId: string, decision: AnalystDecision) => void;
}

export function renderDecisionPanel(host: HTMLElement, run: CompiledRun, s: ViewState, analyst?: AnalystUi) {
  const att = run.fixture.attacker;
  const frag = document.createDocumentFragment();

  frag.append(
    h(
      'section',
      { class: 'card session' },
      h('h3', {}, 'Session'),
      h(
        'dl',
        { class: 'kv' },
        h('dt', {}, 'Actor'),
        h('dd', {}, att.label),
        h('dt', {}, 'Source'),
        h('dd', { class: 'mono' }, att.sourceLabel),
        h('dt', {}, 'Session'),
        h('dd', { class: 'mono' }, att.sessionId),
        h('dt', {}, 'Instrumented'),
        h('dd', {}, att.instrumented ? 'Yes — harness reports tokens' : 'No — tokens unavailable'),
      ),
      h('p', { class: `status-pill st-${s.session}` }, SESSION_LABEL[s.session]),
    ),
  );

  const a = s.assessment;
  frag.append(
    h(
      'section',
      { class: 'card' },
      h('h3', {}, 'Latest assessment'),
      a
        ? h(
            'div',
            {},
            h('p', { class: 'muted' }, `${a.summary} · ${a.evidence?.id ?? ''}`),
            confidenceBar(a.confidence ?? 0, a.basis),
            h('div', { class: 'obs-inf' }, basisList('Observed', 'observed', a.evidence?.observed ?? []), basisList('Inferred', 'inferred', a.inferred ?? [])),
          )
        : h('p', { class: 'empty' }, 'No assessment yet. Press Play or Step to start the run.'),
    ),
  );

  const c = s.classification;
  if (c) {
    frag.append(
      h(
        'section',
        { class: 'card' },
        h('h3', {}, 'Actor classification (TAA)'),
        h('p', {}, c.summary.replace(/^TAA: /, '')),
        h('p', { class: `tag tag-${c.basis}` }, c.basis === 'observed' ? 'Observed via lab instrumentation' : `Inferred · confidence ${(c.confidence ?? 0).toFixed(2)}`),
        c.inferred?.length ? h('ul', { class: 'plain' }, ...c.inferred.map((i) => h('li', {}, i))) : null,
      ),
    );
  }

  frag.append(
    h(
      'section',
      { class: 'card' },
      h('h3', {}, 'Policy decisions'),
      s.decisions.length ? h('div', { class: 'decisions' }, ...s.decisions.map((d) => decisionCard(d, analyst))) : h('p', { class: 'empty' }, 'No rule has matched yet.'),
    ),
  );

  if (analyst?.interactive) {
    frag.append(
      h(
        'section',
        { class: 'card' },
        h('h3', {}, 'Your decisions'),
        analyst.inputs.length
          ? h(
              'ol',
              { class: 'plain' },
              ...analyst.inputs.map((i) => h('li', {}, h('span', { class: 'mono' }, `T+${(i.atT / 1000).toFixed(2)}s ${i.ruleId}`), ` ${i.decision}`)),
            )
          : h('p', { class: 'empty' }, 'None yet. Playback pauses when a rule needs a human; your choice is recorded as an event and replays exactly.'),
      ),
    );
  }

  frag.append(
    h(
      'p',
      { class: 'footnote' },
      'ADA, TAA, CRA and CLA follow the GATRA agent roles defined in this repository (src/types). In this lab they are simulated in the browser; no deployed agent is called.',
    ),
  );
  host.replaceChildren(frag);
}

function confidenceBar(value: number, basis: string) {
  const bar = h('div', { class: 'conf', role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': '1', 'aria-valuenow': value.toFixed(2), 'aria-label': 'Confidence' });
  const fill = h('span', { class: 'conf-fill' });
  fill.style.width = `${Math.round(value * 100)}%`;
  bar.append(fill);
  return h('div', { class: 'conf-row' }, bar, h('span', { class: 'mono' }, `${value.toFixed(2)} ${basis}`));
}

function basisList(title: string, basis: 'observed' | 'inferred', items: string[]) {
  return h(
    'div',
    { class: `basis basis-${basis}` },
    h('h4', {}, title),
    items.length ? h('ul', { class: 'plain' }, ...items.map((i) => h('li', {}, i))) : h('p', { class: 'muted' }, 'None'),
  );
}

function decisionButtons(ruleId: string, onDecide: AnalystUi['onDecide']) {
  const mk = (decision: AnalystDecision, label: string, cls: string) => {
    const b = h('button', { type: 'button', class: `btn ${cls}`, 'data-decide': decision, 'data-rule': ruleId }, label);
    b.addEventListener('click', () => onDecide(ruleId, decision));
    return b;
  };
  return h(
    'div',
    { class: 'decide', role: 'group', 'aria-label': `Decision for ${ruleId}` },
    mk('approve', 'Approve', 'btn-approve'),
    mk('reject', 'Reject', 'btn-reject'),
    mk('observe', 'Keep observing', ''),
  );
}

function decisionCard(d: DecisionView, analyst?: AnalystUi) {
  const e = d.decision;
  const awaiting = analyst?.interactive && d.approval === 'pending' && e.data?.mode === 'approval';
  return h(
    'article',
    { class: `decision mode-${e.data?.mode}` },
    h('header', {}, h('span', { class: 'mono rule' }, e.ruleId ?? ''), h('span', { class: `approval ap-${d.approval}` }, APPROVAL_LABEL[d.approval])),
    h('p', { class: 'decision-title' }, e.summary.replace(/^R-[A-Z]+-\d+ /, '')),
    h('p', { class: 'rationale' }, e.rationale ?? ''),
    h('p', { class: 'trace mono' }, `Matched: ${e.data?.trace ?? ''} · evidence ${e.evidence?.id ?? '—'} · ${e.data?.policyVersion ?? ''}`),
    d.approvalNote ? h('p', { class: 'analyst-note' }, `Analyst: ${d.approvalNote}`) : null,
    awaiting ? decisionButtons(e.ruleId!, analyst!.onDecide) : null,
    d.results.length
      ? h(
          'ul',
          { class: 'results' },
          ...d.results.map((r) => h('li', { class: `res res-${r.data?.status}` }, h('span', { class: 'mono' }, String(r.data?.status)), ' ', r.summary)),
        )
      : null,
  );
}

/* ------------------------------------------------------------------ */
/* Timeline                                                             */
/* ------------------------------------------------------------------ */

export class Timeline {
  private rendered = 0;
  private list: HTMLOListElement;
  private host: HTMLElement;
  constructor(host: HTMLElement) {
    this.host = host;
    this.list = h('ol', { class: 'timeline', 'aria-live': 'polite', 'aria-relevant': 'additions' });
    host.append(this.list);
  }
  reset() {
    this.rendered = 0;
    this.list.replaceChildren();
  }
  render(run: CompiledRun, count: number) {
    if (count < this.rendered) this.reset();
    for (let i = this.rendered; i < count; i++) this.list.append(row(run.events[i]!));
    this.rendered = count;
    this.host.scrollTop = this.host.scrollHeight;
  }
}

function row(e: LabEvent) {
  const details = h(
    'dl',
    { class: 'kv detail' },
    h('dt', {}, 'Event'),
    h('dd', { class: 'mono' }, `${e.id} (seq ${e.seq})`),
    h('dt', {}, 'Basis'),
    h('dd', {}, e.basis + (e.confidence !== undefined ? ` · confidence ${e.confidence.toFixed(2)}` : '')),
    e.evidence ? h('dt', {}, 'Evidence') : null,
    e.evidence ? h('dd', {}, `${e.evidence.id} · ${e.evidence.type} · ${e.evidence.observed.join('; ')}`) : null,
    e.rationale ? h('dt', {}, 'Rationale') : null,
    e.rationale ? h('dd', {}, e.rationale) : null,
    e.data ? h('dt', {}, 'Data') : null,
    e.data ? h('dd', { class: 'mono' }, JSON.stringify(e.data)) : null,
    h('dt', {}, 'Prev hash'),
    h('dd', { class: 'mono' }, e.prevHash),
    h('dt', {}, 'Hash'),
    h('dd', { class: 'mono' }, e.hash),
  );
  return h(
    'li',
    { class: `ev ${packetClass(e)} basis-${e.basis}`, 'data-kind': e.kind },
    h(
      'details',
      {},
      h(
        'summary',
        {},
        h('span', { class: 'mono t' }, fmtT(e.t)),
        h('span', { class: 'kind' }, e.kind),
        h('span', { class: 'ev-text' }, e.summary),
        h('span', { class: 'mono ids' }, `${e.evidence?.id ?? ''} ${e.hash.slice(0, 8)}`),
      ),
      details,
    ),
  );
}

/* ------------------------------------------------------------------ */
/* Economics                                                            */
/* ------------------------------------------------------------------ */

interface MetricRow {
  label: string;
  get: (m: RunMetrics) => string;
  hint?: string;
}

export function renderEconomics(host: HTMLElement, rows: ComparisonRow[], run: CompiledRun) {
  const instrumented = run.fixture.attacker.instrumented;
  const metrics: MetricRow[] = [
    { label: 'Attacker tool calls', get: (m) => String(m.toolCalls) },
    { label: 'Attacker active time', get: (m) => `${m.attackerActiveSec}s` },
    { label: 'Time to contain', get: (m) => (m.timeToContainSec === null ? 'Not contained' : `${m.timeToContainSec}s`) },
    {
      label: 'Attacker tokens',
      get: (m) => (m.attackerTokens === null ? 'Unavailable' : m.attackerTokens.toLocaleString('en-US')),
      hint: instrumented ? 'Reported by our lab harness' : 'Attacker is not instrumented, so tokens cannot be measured. They are never estimated.',
    },
    { label: 'Real objectives reached', get: (m) => `${m.objectivesCompleted} of ${m.objectivesPlanned}` },
    { label: 'Decoy interactions', get: (m) => String(m.decoyInteractions) },
    { label: 'Decoy dwell time', get: (m) => `${m.decoyDwellSec}s` },
    { label: 'Egress denied', get: (m) => String(m.egressDenied) },
    { label: 'Benign sessions disrupted', get: (m) => String(m.benignDisruptions) },
    { label: 'Analyst minutes', get: (m) => m.analystMinutes.toFixed(2) },
    { label: 'Defender cost (units)', get: (m) => m.defenderCost.toFixed(2), hint: 'Synthetic cost model; see below' },
  ];

  const table = h(
    'table',
    { class: 'econ' },
    h('caption', {}, `Same seed (${run.seed}), same attacker plan, three deception modes`),
    h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Metric'), ...rows.map((r) => h('th', { scope: 'col', class: r.mode === run.mode ? 'current' : undefined }, r.label)))),
    h(
      'tbody',
      {},
      ...metrics.map((m) =>
        h(
          'tr',
          {},
          h('th', { scope: 'row', title: m.hint }, m.label),
          ...rows.map((r) => {
            const v = m.get(r.metrics);
            return h('td', { class: [r.mode === run.mode ? 'current' : '', v === 'Unavailable' ? 'na' : ''].join(' ').trim() || undefined, title: m.hint }, v);
          }),
        ),
      ),
    ),
  );

  const cost = COST_MODEL;
  host.replaceChildren(
    h(
      'div',
      { class: 'econ-wrap' },
      h('p', { class: 'exp-head' }, h('span', { class: 'badge badge-synthetic' }, 'Synthetic · illustrative'), h('span', { class: 'muted small' }, 'Simulator fixture output. For measured lab runs see Experiments.')),
      table,
      !instrumented ? h('p', { class: 'na-note' }, 'Attacker tokens are unavailable: this attacker is not instrumented. Fast or adaptive requests are not treated as evidence of an AI agent.') : null,
      run.fixture.hypothesis ? h('p', { class: 'hypothesis' }, run.fixture.hypothesis) : null,
      h(
        'details',
        { class: 'cost-model' },
        h('summary', {}, 'How defender cost is calculated'),
        h(
          'p',
          { class: 'mono' },
          `${cost.perTelemetryEvent}/telemetry event + ${cost.perAssessment}/assessment + ${cost.perContainmentAction}/executed action + ${cost.perAnalystMinute}/analyst minute + decoy hosting (none ${cost.decoyHostingPerRun.none}, static ${cost.decoyHostingPerRun.static}, adaptive ${cost.decoyHostingPerRun.adaptive}).`,
        ),
      ),
      h('p', { class: 'footnote' }, 'All values come from synthetic fixtures in this simulator. They are not measurements of any production system and do not predict real-world performance.'),
    ),
  );
}

/* ------------------------------------------------------------------ */
/* Policy editor                                                        */
/* ------------------------------------------------------------------ */

export function renderPolicy(host: HTMLElement, policy: PolicyConfig, modified: boolean, onToggle: (ruleId: string, enabled: boolean) => void, onReset: () => void) {
  const rules = [...policy.rules].sort((a, b) => b.priority - a.priority);
  host.replaceChildren(
    h(
      'div',
      { class: 'policy' },
      h(
        'p',
        { class: 'muted' },
        `Policy ${policy.version}${modified ? ' (modified for this session)' : ''}. Egress: default deny; allowed only to `,
        h('span', { class: 'mono' }, policy.egress.allow.map((a) => `${a.host}:${a.port}`).join(', ') || 'nothing'),
        '.',
      ),
      h(
        'ul',
        { class: 'rules' },
        ...rules.map((r) => {
          const input = h('input', { type: 'checkbox', id: `rule-${r.id}` });
          input.checked = r.enabled;
          input.addEventListener('change', () => onToggle(r.id, input.checked));
          return h(
            'li',
            { class: `rule mode-${r.mode}` },
            input,
            h(
              'label',
              { for: `rule-${r.id}` },
              h('span', { class: 'mono' }, r.id),
              ' ',
              h('strong', {}, r.title),
              h('span', { class: 'rule-mode' }, ` ${r.mode} → ${r.actions.join(', ')}`),
              h('span', { class: 'rule-why' }, r.rationale),
            ),
          );
        }),
      ),
      modified ? resetButton(onReset) : null,
    ),
  );
}

function resetButton(onReset: () => void) {
  const b = h('button', { type: 'button', class: 'btn' }, 'Restore default policy');
  b.addEventListener('click', onReset);
  return b;
}
