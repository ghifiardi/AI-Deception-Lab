/**
 * Side panel and comparison table for Defense V2 runs (simulated swarm or a
 * recorded VM1/VM2 result). DOM is built with textContent only.
 */
import type { CompiledRun } from '../engine/simulator.ts';
import { V2_MODES, V2_OUTCOMES, V2_ROLES, efficacyOf, simulateV2Swarm } from '../engine/v2.ts';
import type { V2Efficacy, V2Mode, V2Outcome } from '../engine/v2.ts';
import { h } from './panels.ts';

const OUTCOME_LABEL: Record<V2Outcome, string> = {
  success: 'exported',
  revoked: 'revoked',
  blocked: 'blocked',
  'no-objective': 'no objective',
  error: 'error (excluded)',
};

export function renderV2Panel(host: HTMLElement, run: CompiledRun, count: number) {
  const v2 = run.v2!;
  const rec = v2.recorded;
  const shown = run.events.slice(0, count);
  const done = new Map<string, V2Outcome>();
  let bait = 0;
  let canary = 0;
  let revoked = 0;
  let egressDenied = 0;
  let egressAllowed = 0;
  let lastRevoke = '';
  for (const e of shown) {
    if (e.kind === 'agent.outcome') done.set(String(e.data?.agentId), e.data?.outcome as V2Outcome);
    else if (e.kind === 'decoy.response') bait++;
    else if (e.kind === 'canary.used') canary++;
    else if (e.kind === 'containment.result') { revoked++; lastRevoke = e.summary; }
    else if (e.kind === 'egress.denied') egressDenied++;
    else if (e.kind === 'egress.allowed') egressAllowed++;
  }

  const source = h(
    'section',
    { class: 'card' },
    h('h3', {}, v2.source === 'recorded' ? 'Recorded engagement' : 'Simulated swarm'),
    h(
      'dl',
      { class: 'kv' },
      h('dt', {}, 'Defense mode'),
      h('dd', {}, `${v2.mode}${rec ? (rec.attested ? ' · attested by the gateway' : ' · NOT attested') : ' · simulated'}`),
      rec ? h('dt', {}, 'Stack') : null,
      rec ? h('dd', { class: 'mono' }, rec.stackId ?? 'unknown') : null,
      rec ? h('dt', {}, 'Engagement') : null,
      rec ? h('dd', { class: 'mono' }, rec.engagementId) : null,
      rec ? h('dt', {}, 'Provider · seed') : null,
      rec ? h('dd', {}, `${rec.provider} · ${rec.seed ?? '—'}`) : null,
      h('dt', {}, 'Agents shown'),
      h('dd', {}, v2.sample && v2.totalAgents > v2.agents.length ? `${v2.agents.length} of ${v2.totalAgents} (one per role × outcome)` : `${v2.agents.length} of ${v2.totalAgents}`),
    ),
    rec?.attested === false ? h('p', { class: 'v2-warn' }, 'The gateway did not attest this mode. Treat the mode label as unverified.') : null,
  );

  const many = v2.agents.length > 24;
  const agents = h(
    'section',
    { class: 'card' },
    h('h3', {}, 'Agents'),
    many
      ? tallyTable(v2.agents.filter((a) => done.has(a.agentId)).map((a) => [a.role, a.outcome]), `${done.size} of ${v2.agents.length} finished in this replay`)
      : h(
          'table',
          { class: 'econ v2-agents' },
          h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Agent'), h('th', { scope: 'col' }, 'Calls'), h('th', { scope: 'col' }, 'Outcome'))),
          h(
            'tbody',
            {},
            ...v2.agents.map((a) => {
              const o = done.get(a.agentId);
              return h(
                'tr',
                {},
                h('th', { scope: 'row', class: 'mono' }, a.agentId),
                h('td', {}, String(a.calls.length)),
                h('td', { class: o ? `v2-o v2-o-${o}${a.kind === 'legit' ? '-legit' : ''}` : 'muted' }, o ? OUTCOME_LABEL[o] : '…'),
              );
            }),
          ),
        ),
  );

  const gateway = h(
    'section',
    { class: 'card' },
    h('h3', {}, 'Gateway decisions'),
    h(
      'dl',
      { class: 'kv' },
      h('dt', {}, 'Bait served'),
      h('dd', {}, String(bait)),
      h('dt', {}, 'Canary used'),
      h('dd', {}, String(canary)),
      h('dt', {}, 'Peers revoked'),
      h('dd', {}, String(revoked)),
      h('dt', {}, 'Egress denied'),
      h('dd', { class: egressAllowed ? 'v2-o-success' : egressDenied ? 'v2-o-revoked' : '' }, egressAllowed ? `${egressDenied} denied · ${egressAllowed} ALLOWED` : String(egressDenied)),
    ),
    lastRevoke ? h('p', { class: 'muted small' }, lastRevoke) : null,
    egressDenied || egressAllowed ? h('p', { class: 'muted small' }, egressAllowed ? 'An outbound callout was allowed — data could leave. Check the egress policy.' : 'Every outbound callout was denied by the default-deny egress policy (lab network is also internal: no route off the host).') : null,
    v2.mode !== 'defended' ? h('p', { class: 'muted small' }, `DEFENSE_MODE=${v2.mode}: no bait and no revocation in this mode. Egress is default-deny in every mode.`) : null,
  );

  const totals = rec && v2.source === 'recorded' && run.v2?.recorded ? recordedTotals(run) : null;

  host.replaceChildren(
    source,
    gateway,
    agents,
    totals ?? '',
    h(
      'p',
      { class: 'footnote' },
      'Live Defense V2 has no ADA/TAA scoring and no analyst approval: on the first use of a canary key the gateway revokes that peer for 15 minutes. Those nodes are dimmed in the topology.',
    ),
  );
}

function recordedTotals(run: CompiledRun) {
  const rec = run.v2!.recorded!;
  const e = rec.efficacy;
  return h(
    'section',
    { class: 'card' },
    h('h3', {}, 'Recorded totals (authoritative)'),
    e
      ? h(
          'dl',
          { class: 'kv' },
          h('dt', {}, 'Red exported'),
          h('dd', { class: e.redCompromised ? 'v2-o-success' : '' }, `${e.redCompromised} / ${e.validRed}`),
          h('dt', {}, 'Red revoked'),
          h('dd', {}, String(e.redRevoked)),
          h('dt', {}, 'Red blocked · no objective'),
          h('dd', {}, `${e.redBlocked} · ${e.redNoObjective}`),
          h('dt', {}, 'Legit exported'),
          h('dd', {}, `${e.legitExported} / ${e.validLegit}`),
          rec.egress ? h('dt', {}, 'Egress denied') : null,
          rec.egress ? h('dd', { class: rec.egress.allowed ? 'v2-o-success' : '' }, `${rec.egress.denied} / ${rec.egress.attempts}${rec.egress.allowed ? ` · ${rec.egress.allowed} ALLOWED` : ''}`) : null,
          h('dt', {}, 'Excluded errors'),
          h('dd', {}, String(e.excludedErrors)),
          h('dt', {}, 'Interpretable'),
          h('dd', {}, rec.interpretable === null ? 'unknown' : rec.interpretable ? 'yes' : `no — ${rec.notes.join('; ')}`),
        )
      : h('p', { class: 'empty' }, 'This file has no efficacy summary.'),
  );
}

function tallyTable(pairs: [string, V2Outcome][], caption: string) {
  const n = (role: string, o: V2Outcome) => pairs.filter(([r, x]) => r === role && x === o).length;
  return h(
    'table',
    { class: 'econ' },
    h('caption', {}, caption),
    h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Role'), ...V2_OUTCOMES.map((o) => h('th', { scope: 'col' }, OUTCOME_LABEL[o])))),
    h('tbody', {}, ...V2_ROLES.map((r) => h('tr', {}, h('th', { scope: 'row' }, r), ...V2_OUTCOMES.map((o) => h('td', {}, String(n(r, o))))))),
  );
}

/** Economics tab for V2: the three modes side by side, plus the recorded run against its prediction. */
export function renderV2Economics(host: HTMLElement, run: CompiledRun) {
  const v2 = run.v2!;
  const sims = Object.fromEntries(V2_MODES.map((m) => [m, simulateV2Swarm(m)])) as Record<V2Mode, ReturnType<typeof simulateV2Swarm>>;
  const effs = Object.fromEntries(V2_MODES.map((m) => [m, efficacyOf(sims[m])])) as Record<V2Mode, V2Efficacy>;
  const egressOf = (agents: ReturnType<typeof simulateV2Swarm>) => {
    const calls = agents.flatMap((a) => a.calls).filter((c) => c.path.split('?')[0] === '/api/v1/egress');
    return { denied: calls.filter((c) => c.status === 403).length, allowed: calls.filter((c) => c.status === 200).length, attempts: calls.length };
  };
  const rows: [string, (m: V2Mode) => string][] = [
    ['Red agents that exported', (m) => `${effs[m].redCompromised} / ${effs[m].validRed}`],
    ['Red agents revoked', (m) => String(effs[m].redRevoked)],
    ['Red agents blocked', (m) => String(effs[m].redBlocked)],
    ['Red agents with no objective', (m) => String(effs[m].redNoObjective)],
    ['Egress callouts denied', (m) => { const e = egressOf(sims[m]); return e.allowed ? `${e.denied} / ${e.attempts} · ${e.allowed} allowed` : `${e.denied} / ${e.attempts}`; }],
    ['Legit clients that exported', (m) => `${effs[m].legitExported} / ${effs[m].validLegit}`],
  ];
  const modeTable = h(
    'table',
    { class: 'econ' },
    h('caption', {}, 'Simulated: one agent per role, per DEFENSE_MODE (tests check this against the real gateway)'),
    h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, `Per ${V2_ROLES.length} agents`), ...V2_MODES.map((m) => h('th', { scope: 'col', class: m === v2.mode ? 'current' : undefined }, m)))),
    h('tbody', {}, ...rows.map(([label, get]) => h('tr', {}, h('th', { scope: 'row' }, label), ...V2_MODES.map((m) => h('td', { class: m === v2.mode ? 'current' : undefined }, get(m)))))),
  );

  let check: HTMLElement | null = null;
  if (v2.source === 'recorded' && v2.recorded) {
    // Prediction vs recording, per role, errors excluded.
    const predicted = Object.fromEntries(sims[v2.mode].map((a) => [a.role, a.outcome]));
    const body = V2_ROLES.map((role) => {
      const mine = v2.allAgents.filter((a) => a.role === role && a.outcome !== 'error');
      const match = mine.filter((a) => a.outcome === predicted[role]).length;
      return h(
        'tr',
        {},
        h('th', { scope: 'row' }, role),
        h('td', {}, OUTCOME_LABEL[predicted[role] as V2Outcome]),
        h('td', { class: mine.length && match === mine.length ? 'v2-o-match' : 'v2-o-miss' }, mine.length ? `${match} / ${mine.length}` : '—'),
      );
    });
    check = h(
      'div',
      {},
      h('h4', { class: 'v2-sub' }, `Recorded vs simulated prediction (DEFENSE_MODE=${v2.mode})`),
      h(
        'table',
        { class: 'econ' },
        h('caption', {}, `All ${v2.allAgents.length} recorded agents, errors excluded`),
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Role'), h('th', { scope: 'col' }, 'Predicted'), h('th', { scope: 'col' }, 'Recorded match'))),
        h('tbody', {}, ...body),
      ),
    );
  }

  host.replaceChildren(
    h(
      'div',
      { class: 'econ-wrap' },
      h(
        'p',
        { class: 'exp-head' },
        h('span', { class: `badge ${v2.source === 'recorded' ? 'badge-measured' : 'badge-synthetic'}` }, v2.source === 'recorded' ? 'Recorded · lab VM' : 'Synthetic · mirrors live V2'),
        h('span', { class: 'muted small' }, 'Same vocabulary as the GCP Lab and Live tabs.'),
      ),
      modeTable,
      check,
      h('p', { class: 'footnote' }, 'Simulator modes map to DEFENSE_MODE: None = baseline, Static = hardened, Adaptive = defended. Recorded figures come from the result file; nothing here is a production measurement.'),
    ),
  );
}
