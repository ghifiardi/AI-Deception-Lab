/**
 * Discrete-event compiler.
 *
 * compileRun() turns (scenario, mode, seed, policy) into a complete, ordered,
 * hash-chained event log. The fixture only scripts the attacker's plan and the
 * analyst's answers; telemetry, agent assessments, policy decisions and
 * containment are DERIVED here by the engine.
 *
 * Determinism: no wall-clock, no Math.random, no I/O. Same inputs give
 * byte-identical output, which tests verify.
 */
import { executeAction } from './containment.ts';
import { GENESIS_HASH, hashRecord } from './hash.ts';
import { DEFAULT_POLICY, TELEMETRY_COLLECTOR, evaluateEgress, evaluatePolicy, isApprovedSource } from './policy.ts';
import type { PolicyConfig, PolicyRule } from './policy.ts';
import { createRng } from './rng.ts';
import { buildScenario } from './scenarios.ts';
import { V2_MODE_FOR, compileSimulatedV2 } from './v2.ts';
import type { V2Info } from './v2.ts';
import type {
  ActionType,
  AnalystConfig,
  AnalystInput,
  AttackStep,
  DeceptionMode,
  DraftEvent,
  EvidenceRef,
  LabEvent,
  NodeId,
  ScenarioFixture,
  ScenarioId,
  Zone,
} from './types.ts';

export const NODE_ZONE: Record<NodeId, Zone> = {
  attacker: 'internet',
  scanner: 'internet',
  legit: 'internet',
  entry: 'entry',
  'mock-app': 'mock-target',
  'hp-api': 'deception',
  'decoy-docs': 'deception',
  'decoy-workload': 'deception',
  collector: 'telemetry',
  'egress-gw': 'egress',
  'internet-out': 'egress',
  ADA: 'analysis',
  TAA: 'analysis',
  policy: 'control',
  analyst: 'control',
  CRA: 'control',
  CLA: 'control',
  harness: 'control',
};

export const DECOY_NODES: readonly NodeId[] = ['hp-api', 'decoy-docs', 'decoy-workload'];

/** Sensor-to-decision latencies (simulated ms). Fixed so runs are explainable. */
export const LATENCY = {
  decoyResponse: 90,
  sensorToCollector: 150,
  collectorToADA: 250,
  adaToTAA: 400,
  toPolicy: 200,
  toApproval: 100,
  toCRA: 150,
  actionToResult: 300,
  egressVerdict: 20,
} as const;

const RATE_WINDOW_MS = 3000;
const RATE_THRESHOLD = 5;
const THROTTLE_FACTOR = 2;
export const TOKEN_COST_PER_1K = 0.6;

const CONFIDENCE: Record<EvidenceRef['type'], number> = {
  'decoy-interaction': 0.9,
  'canary-use': 0.98,
  'rate-anomaly': 0.55,
  'egress-attempt': 0.92,
  'harness-telemetry': 1,
  'allowlist-match': 1,
};

const INFERRED: Record<EvidenceRef['type'], string[]> = {
  'decoy-interaction': ['Session is enumerating non-public endpoints', 'Intent is likely reconnaissance (not confirmed)'],
  'canary-use': ['Credential was harvested from decoy content', 'Actor is attempting authenticated access'],
  'rate-anomaly': ['Requests are probably automated', 'Rate alone does not indicate an AI agent or malicious intent'],
  'egress-attempt': ['Possible staging for exfiltration or a command-and-control callback'],
  'harness-telemetry': ['Experiment bound reached; agent must stop'],
  'allowlist-match': [],
};

export interface CompileOptions {
  scenario: ScenarioId;
  mode: DeceptionMode;
  seed: number;
  policy?: PolicyConfig;
  /** Default: scripted analyst from the fixture. */
  analyst?: AnalystConfig;
}

const DECISIONS = new Set(['approve', 'reject', 'observe']);

/** Returns a list of problems; empty means the inputs are valid. */
export function validateAnalystInputs(inputs: readonly AnalystInput[]): string[] {
  const errors: string[] = [];
  inputs.forEach((inp, i) => {
    if (typeof inp.ruleId !== 'string' || !/^R-[A-Z]+-\d{2}$/.test(inp.ruleId)) errors.push(`input ${i}: invalid ruleId`);
    if (!DECISIONS.has(inp.decision)) errors.push(`input ${i}: decision must be approve, reject or observe`);
    if (!Number.isFinite(inp.atT) || inp.atT < 0 || inp.atT > 3_600_000) errors.push(`input ${i}: atT out of range`);
    if (inp.note !== undefined && (typeof inp.note !== 'string' || inp.note.length > 280)) errors.push(`input ${i}: note too long`);
  });
  return errors;
}

export interface CompiledRun {
  fixture: ScenarioFixture;
  mode: DeceptionMode;
  seed: number;
  policy: PolicyConfig;
  analyst: AnalystConfig;
  events: LabEvent[];
  /** Present for Defense V2 runs (simulated swarm or recorded replay). */
  v2?: V2Info;
}

interface Scheduled {
  draft: DraftEvent;
  order: number;
}

export function compileRun(opts: CompileOptions): CompiledRun {
  const policy = opts.policy ?? DEFAULT_POLICY;
  const analyst: AnalystConfig = opts.analyst ?? { mode: 'scripted' };
  // Defense V2 mirrors the live gateway: no ADA/TAA, no analyst, its own rule.
  if (opts.scenario === 'swarm-v2') return { ...compileSimulatedV2(V2_MODE_FOR[opts.mode], opts.seed), policy, analyst: { mode: 'scripted' } };
  if (analyst.mode === 'interactive') {
    const errors = validateAnalystInputs(analyst.inputs);
    if (errors.length) throw new Error(`Invalid analyst inputs: ${errors.join('; ')}`);
  }
  const consumedInputs = new Set<number>();
  const fixtureRng = createRng(opts.seed);
  const timingRng = createRng(opts.seed ^ 0x9e3779b9);
  const idRng = createRng(opts.seed ^ 0x85ebca6b);
  const fixture = buildScenario(opts.scenario, opts.mode, fixtureRng);
  const att = fixture.attacker;
  const attackerNode: NodeId = att.kind === 'benign-scanner' ? 'scanner' : 'attacker';
  const evPrefix = { 'api-canary': 'A', 'false-positive': 'B', 'agentic-decoy': 'C', 'egress-block': 'D', 'swarm-v2': 'V' }[fixture.id];

  const events: LabEvent[] = [];
  const queue: Scheduled[] = [];
  let order = 0;
  let evidenceSeq = 0;

  // Simulated state
  let terminated = false;
  let halted = false;
  let throttle = 1;
  let egressSealed = false;
  let canaryId: string | null = null;
  let classified = false;
  let agentSteps = 0;
  let tokensUsed = 0;
  const quarantined = new Set<NodeId>();
  const firedRules = new Set<string>();
  const evidenceCounts = new Map<EvidenceRef['type'], number>();
  const requestTimes: number[] = [];
  let rateFlagged = false;
  const pendingActions = new Map<string, { actions: ActionType[]; evidence?: EvidenceRef; node: NodeId }>();

  const schedule = (draft: DraftEvent) => {
    queue.push({ draft, order: order++ });
    queue.sort((a, b) => a.draft.t - b.draft.t || a.order - b.order);
  };

  const emit = (draft: DraftEvent): LabEvent => {
    const seq = events.length + 1;
    const prevHash = events.length ? events[events.length - 1]!.hash : GENESIS_HASH;
    const body = { ...draft, seq, id: `EVT-${String(seq).padStart(4, '0')}`, prevHash };
    const ev: LabEvent = { ...body, hash: hashRecord(body) };
    events.push(ev);
    handle(ev);
    return ev;
  };

  const newEvidence = (type: EvidenceRef['type'], observed: string[]): EvidenceRef => ({
    id: `EV-${evPrefix}-${String(++evidenceSeq).padStart(3, '0')}`,
    type,
    observed,
  });

  /** `subject` = the lab node the evidence is about (defaults to the sensor). */
  const telemetry = (t: number, from: NodeId, evidence: EvidenceRef, subject: NodeId = from) =>
    schedule({
      t: t + LATENCY.sensorToCollector,
      kind: 'telemetry.ingest',
      actor: 'collector',
      from,
      to: 'collector',
      zone: 'telemetry',
      summary: `Sensor ${from} → collector: ${evidence.type} (${evidence.id})`,
      basis: 'observed',
      evidence,
      data: { subject },
    });

  const actionTarget = (action: ActionType, node: NodeId): { target: string; to: NodeId } => {
    switch (action) {
      case 'terminate_session':
      case 'throttle_requests':
        return { target: att.sessionId, to: 'entry' };
      case 'quarantine_workload':
        return { target: node, to: node };
      case 'block_lab_egress':
        return { target: 'egress-gw', to: 'egress-gw' };
      default:
        return { target: att.sourceLabel, to: 'analyst' };
    }
  };

  const scheduleActions = (t: number, ruleId: string, actions: ActionType[], node: NodeId, dryRun: boolean, evidence?: EvidenceRef) => {
    actions.forEach((action, i) => {
      const { target, to } = actionTarget(action, node);
      const proposal = action.startsWith('propose_');
      schedule({
        t: t + LATENCY.toCRA + i * 60,
        kind: 'containment.action',
        actor: 'CRA',
        from: 'CRA',
        to,
        zone: 'control',
        summary: `${proposal || dryRun ? 'Dry-run' : 'Execute'}: ${action} → ${target}`,
        basis: 'observed',
        ruleId,
        action,
        dryRun: proposal || dryRun,
        approval: proposal ? 'pending' : undefined,
        evidence,
        data: { target },
      });
    });
  };

  function handle(ev: LabEvent): void {
    switch (ev.kind) {
      case 'telemetry.ingest': {
        const evidence = ev.evidence!;
        const count = (evidenceCounts.get(evidence.type) ?? 0) + 1;
        evidenceCounts.set(evidence.type, count);
        const basisObserved = evidence.type === 'harness-telemetry';
        schedule({
          t: ev.t + LATENCY.collectorToADA,
          kind: 'agent.assessment',
          actor: 'ADA',
          from: 'collector',
          to: 'ADA',
          zone: 'analysis',
          summary: `ADA: ${evidence.type} #${count} for ${att.sessionId}`,
          basis: basisObserved ? 'observed' : 'inferred',
          confidence: CONFIDENCE[evidence.type],
          evidence,
          inferred: INFERRED[evidence.type],
          data: { evidenceCount: count, node: String(ev.data?.subject ?? ev.from ?? 'entry') },
        });
        return;
      }
      case 'agent.assessment': {
        const evidence = ev.evidence!;
        if (!classified) {
          classified = true;
          schedule(classify(ev.t + LATENCY.adaToTAA));
        }
        const matches = evaluatePolicy(policy, {
          evidenceType: evidence.type,
          confidence: ev.confidence ?? 0,
          evidenceCount: Number(ev.data?.evidenceCount ?? 1),
          sourceLabel: att.sourceLabel,
        });
        let delay = 0;
        for (const { rule, trace } of matches) {
          if (firedRules.has(rule.id)) continue;
          firedRules.add(rule.id);
          schedule(decision(ev.t + LATENCY.toPolicy + delay, rule, trace, ev));
          delay += 40;
        }
        return;
      }
      case 'policy.decision': {
        const actions = String(ev.data?.actions ?? '')
          .split(',')
          .filter(Boolean) as ActionType[];
        const node = (ev.data?.node as NodeId | null) ?? 'entry';
        const mode = ev.data?.mode;
        if (mode === 'auto') scheduleActions(ev.t, ev.ruleId!, actions, node, false, ev.evidence);
        else if (mode === 'dry-run') scheduleActions(ev.t, ev.ruleId!, actions, node, true, ev.evidence);
        else {
          pendingActions.set(ev.ruleId!, { actions, evidence: ev.evidence, node });
          schedule({
            t: ev.t + LATENCY.toApproval,
            kind: 'approval.requested',
            actor: 'policy',
            from: 'policy',
            to: 'analyst',
            zone: 'control',
            summary: `Analyst approval requested for ${ev.ruleId} (${actions.join(', ')})`,
            basis: 'observed',
            ruleId: ev.ruleId,
            approval: 'pending',
            evidence: ev.evidence,
          });
        }
        return;
      }
      case 'approval.requested': {
        let decision: 'approve' | 'reject' | 'observe';
        let atT: number;
        let note: string;
        let source: 'scripted' | 'interactive';
        let inputIndex: number | null = null;
        if (analyst.mode === 'interactive') {
          const idx = analyst.inputs.findIndex((inp, i) => !consumedInputs.has(i) && inp.ruleId === ev.ruleId && inp.atT >= ev.t);
          if (idx < 0) return; // stays pending until a human decides
          consumedInputs.add(idx);
          const inp = analyst.inputs[idx]!;
          decision = inp.decision;
          atT = Math.max(inp.atT, ev.t + 1);
          note = inp.note ?? '';
          source = 'interactive';
          inputIndex = idx;
        } else {
          const script = fixture.analyst[ev.ruleId!];
          if (!script) return; // remains pending
          decision = script.decision === 'approve' ? 'approve' : 'reject';
          atT = ev.t + script.afterMs;
          note = script.note;
          source = 'scripted';
        }
        const kind = decision === 'approve' ? 'approval.granted' : decision === 'reject' ? 'approval.denied' : 'approval.deferred';
        const verb = decision === 'approve' ? 'approved' : decision === 'reject' ? 'rejected' : 'chose to keep observing for';
        schedule({
          t: atT,
          kind,
          actor: 'analyst',
          from: 'analyst',
          to: decision === 'approve' ? 'CRA' : 'policy',
          zone: 'control',
          summary: `Analyst ${verb} ${ev.ruleId}${note ? `: ${note}` : ''}`,
          basis: 'observed',
          ruleId: ev.ruleId,
          approval: decision === 'approve' ? 'approved' : decision === 'reject' ? 'denied' : 'deferred',
          rationale: note || undefined,
          evidence: ev.evidence,
          data: { waitedMs: atT - ev.t, source, inputIndex, decision },
        });
        return;
      }
      case 'approval.deferred': {
        // Keep watching: no action now, and the rule may ask again on new evidence.
        firedRules.delete(ev.ruleId!);
        pendingActions.delete(ev.ruleId!);
        return;
      }
      case 'approval.granted': {
        const p = pendingActions.get(ev.ruleId!);
        if (p) scheduleActions(ev.t, ev.ruleId!, p.actions, p.node, false, p.evidence);
        return;
      }
      case 'containment.action': {
        const already =
          !ev.dryRun &&
          ((ev.action === 'terminate_session' && terminated) ||
            (ev.action === 'throttle_requests' && throttle > 1) ||
            (ev.action === 'block_lab_egress' && egressSealed) ||
            (ev.action === 'quarantine_workload' && quarantined.has(String(ev.data?.target) as NodeId)));
        const result = already
          ? { status: 'already-applied', detail: `${ev.action} on ${ev.data?.target} already in effect; no change` }
          : executeAction({ type: ev.action!, target: String(ev.data?.target), dryRun: ev.dryRun });
        schedule({
          t: ev.t + LATENCY.actionToResult,
          kind: 'containment.result',
          actor: 'CRA',
          from: ev.to,
          to: 'CLA',
          zone: 'control',
          summary: result.detail,
          basis: 'observed',
          ruleId: ev.ruleId,
          action: ev.action,
          dryRun: ev.dryRun,
          approval: ev.approval,
          evidence: ev.evidence,
          data: { status: result.status, target: String(ev.data?.target) },
        });
        return;
      }
      case 'containment.result': {
        if (ev.data?.status !== 'executed') return;
        const target = String(ev.data?.target);
        if (ev.action === 'terminate_session') terminated = true;
        if (ev.action === 'throttle_requests') throttle = THROTTLE_FACTOR;
        if (ev.action === 'quarantine_workload') quarantined.add(target as NodeId);
        if (ev.action === 'block_lab_egress') egressSealed = true;
        return;
      }
      case 'egress.denied': {
        telemetry(
          ev.t,
          'egress-gw',
          newEvidence('egress-attempt', [
            `Destination ${ev.data?.dest}`,
            `Source workload ${ev.data?.source}`,
            `Verdict: ${ev.rationale}`,
          ]),
          String(ev.data?.source) as NodeId,
        );
        return;
      }
      default:
        return;
    }
  }

  function classify(t: number): DraftEvent {
    const base = { t, kind: 'actor.classification' as const, actor: 'TAA' as const, from: 'ADA' as const, to: 'TAA' as const, zone: 'analysis' as const };
    if (att.instrumented) {
      return {
        ...base,
        summary: 'TAA: instrumented lab agent (identity reported by our harness)',
        basis: 'observed',
        evidence: newEvidence('harness-telemetry', ['Harness reports agent id lab-agent-07', 'Per-step token counts reported']),
        inferred: [],
        data: { actorType: 'instrumented-agent', aiAttribution: 'confirmed-by-instrumentation' },
      };
    }
    if (isApprovedSource(policy, att.sourceLabel)) {
      return {
        ...base,
        summary: 'TAA: source matches approved scanner record',
        basis: 'inferred',
        confidence: 0.8,
        evidence: newEvidence('allowlist-match', [`Source ${att.sourceLabel} on approved list`]),
        inferred: ['Likely authorised vulnerability scanning', 'AI attribution: not applicable'],
        data: { actorType: 'benign-scanner', aiAttribution: 'not-attributed' },
      };
    }
    return {
      ...base,
      summary: 'TAA: automation likely; AI attribution not supported by evidence',
      basis: 'inferred',
      confidence: 0.7,
      inferred: [
        'Request timing is regular, consistent with a script',
        'Rapid or adaptive probing alone does not show an AI agent; no instrumentation evidence exists',
      ],
      data: { actorType: 'scripted-automation-likely', aiAttribution: 'not-attributed' },
    };
  }

  function decision(t: number, rule: PolicyRule, trace: string[], assessment: LabEvent): DraftEvent {
    return {
      t,
      kind: 'policy.decision',
      actor: 'policy',
      from: 'ADA',
      to: 'policy',
      zone: 'control',
      summary: `${rule.id} ${rule.title}: ${rule.mode === 'auto' ? 'auto-contain' : rule.mode === 'dry-run' ? 'dry-run proposal' : 'needs analyst approval'} → ${rule.actions.join(', ')}`,
      basis: 'observed',
      confidence: assessment.confidence,
      evidence: assessment.evidence,
      ruleId: rule.id,
      rationale: rule.rationale,
      approval: rule.mode === 'approval' ? 'pending' : rule.mode === 'dry-run' ? 'pending' : 'not-required',
      data: {
        mode: rule.mode,
        actions: rule.actions.join(','),
        trace: trace.join('; '),
        policyVersion: policy.version,
        node: (assessment.data?.node as string | null) ?? 'entry',
      },
    };
  }

  function attackerStep(t: number, s: AttackStep): void {
    if (att.instrumented && fixture.budget) {
      const b = fixture.budget;
      const nextTokens = tokensUsed + (s.tokens ?? 0);
      const bound =
        agentSteps + 1 > b.maxSteps
          ? `steps ${agentSteps + 1} > ${b.maxSteps}`
          : nextTokens > b.maxTokens
            ? `tokens ${nextTokens} > ${b.maxTokens}`
            : t > b.maxSimMs
              ? `time ${t}ms > ${b.maxSimMs}ms`
              : (nextTokens / 1000) * TOKEN_COST_PER_1K > b.maxCostUnits
                ? `cost > ${b.maxCostUnits} units`
                : null;
      if (bound) {
        halted = true;
        emit({
          t,
          kind: 'budget.exhausted',
          actor: 'harness',
          from: 'harness',
          to: attackerNode,
          zone: 'control',
          summary: `Harness stopped the agent before "${s.label}": ${bound}`,
          basis: 'observed',
          data: { bound, steps: agentSteps, tokens: tokensUsed },
        });
        telemetry(t, 'harness', newEvidence('harness-telemetry', [`Bound reached: ${bound}`, `Steps ${agentSteps}, tokens ${tokensUsed}`]));
        return;
      }
      agentSteps++;
      tokensUsed = nextTokens;
    }
    const tokenData: Record<string, number> = att.instrumented ? { tokens: s.tokens ?? 0, tokensCumulative: tokensUsed } : {};

    if (s.kind === 'reasoning') {
      emit({
        t,
        kind: 'attacker.reasoning',
        actor: attackerNode,
        from: attackerNode,
        to: 'harness',
        zone: 'internet',
        summary: `Agent reasoning: ${s.label}`,
        basis: 'observed',
        data: { ...tokenData, toolCall: false, step: s.label },
      });
      return;
    }

    if (s.kind === 'egress') {
      const verdict = evaluateEgress(policy, s.dest ?? '');
      const allowed = verdict.allowed && !egressSealed;
      const quarantinedSrc = quarantined.has(s.target);
      emit({
        t,
        kind: 'egress.attempt',
        actor: s.target,
        from: s.target,
        to: 'egress-gw',
        zone: NODE_ZONE[s.target],
        summary: `${s.target} attempts outbound connection to ${s.dest}`,
        basis: 'observed',
        data: { ...tokenData, toolCall: s.toolCall, dest: s.dest ?? '', step: s.label },
      });
      const reason = quarantinedSrc
        ? `Source workload ${s.target} is quarantined — denied`
        : egressSealed && verdict.allowed
          ? 'Lab egress gateway sealed — denied'
          : verdict.reason;
      schedule({
        t: t + LATENCY.egressVerdict,
        kind: allowed && !quarantinedSrc ? 'egress.allowed' : 'egress.denied',
        actor: 'egress-gw',
        from: 'egress-gw',
        to: allowed && !quarantinedSrc ? 'internet-out' : s.target,
        zone: 'egress',
        summary: `Egress ${allowed && !quarantinedSrc ? 'ALLOWED' : 'DENIED'}: ${s.dest}`,
        basis: 'observed',
        rationale: reason,
        data: {
          dest: s.dest ?? '',
          source: s.target,
          objective: s.objective ? (allowed ? 'real' : 'blocked') : null,
        },
      });
      return;
    }

    // HTTP-style request
    const isDecoy = DECOY_NODES.includes(s.target);
    const refused = quarantined.has(s.target);
    emit({
      t,
      kind: 'attacker.request',
      actor: attackerNode,
      from: attackerNode,
      to: s.target,
      zone: 'internet',
      summary: `${s.path ?? s.label}${refused ? ' — refused (workload quarantined)' : ''}`,
      basis: 'observed',
      data: {
        ...tokenData,
        toolCall: s.toolCall,
        step: s.label,
        decoy: isDecoy,
        refused,
        objective: s.objective && !refused ? (isDecoy ? 'decoy' : 'real') : null,
      },
    });
    if (refused) return;

    requestTimes.push(t);
    while (requestTimes.length && requestTimes[0]! < t - RATE_WINDOW_MS) requestTimes.shift();
    if (!rateFlagged && requestTimes.length >= RATE_THRESHOLD) {
      rateFlagged = true;
      telemetry(
        t,
        isDecoy ? s.target : 'entry',
        newEvidence('rate-anomaly', [`${requestTimes.length} requests within ${RATE_WINDOW_MS / 1000}s from ${att.sourceLabel}`]),
      );
    }

    if (s.usesCanary && canaryId) {
      schedule({
        t: t + 40,
        kind: 'canary.used',
        actor: s.target,
        from: attackerNode,
        to: s.target,
        zone: NODE_ZONE[s.target],
        summary: `Canary credential ${canaryId} presented at ${s.path}`,
        basis: 'observed',
        data: { canaryId },
      });
      telemetry(
        t + 40,
        s.target,
        newEvidence('canary-use', [`Canary ${canaryId} presented by ${att.sourceLabel}`, `Endpoint ${s.path}`, 'Canary was only ever served by decoy-docs']),
      );
    }

    if (isDecoy) {
      schedule({
        t: t + LATENCY.decoyResponse,
        kind: 'decoy.response',
        actor: s.target,
        from: s.target,
        to: attackerNode,
        zone: 'deception',
        summary: `${s.target} served synthetic ${s.decoyLure ? 'adaptive' : 'static'} content`,
        basis: 'observed',
        data: { adaptive: Boolean(s.decoyLure), bytes: 1200 + timingRng.int(0, 3800) },
      });
      if (s.issuesCanary) {
        canaryId = `CANARY-LAB-${idRng.hex(8).toUpperCase()}`;
        schedule({
          t: t + LATENCY.decoyResponse + 5,
          kind: 'canary.issued',
          actor: s.target,
          from: s.target,
          to: attackerNode,
          zone: 'deception',
          summary: `Decoy file embeds synthetic canary credential ${canaryId} (invalid everywhere)`,
          basis: 'observed',
          data: { canaryId },
        });
      }
      telemetry(t, s.target, newEvidence('decoy-interaction', [`${s.path} on ${s.target}`, `Source ${att.sourceLabel}`, `Session ${att.sessionId}`]));
    }
  }

  // ---- run -------------------------------------------------------------
  emit({
    t: 0,
    kind: 'scenario.start',
    actor: 'CLA',
    zone: 'control',
    summary: `${fixture.title} — mode: ${opts.mode}, seed ${opts.seed}`,
    basis: 'observed',
    data: {
      scenario: fixture.id,
      mode: opts.mode,
      seed: opts.seed,
      policyVersion: policy.version,
      attacker: att.label,
      instrumented: att.instrumented,
    },
  });
  const tel = evaluateEgress(policy, TELEMETRY_COLLECTOR);
  emit({
    t: 200,
    kind: tel.allowed ? 'egress.allowed' : 'egress.denied',
    actor: 'egress-gw',
    from: 'egress-gw',
    to: 'collector',
    zone: 'egress',
    summary: `Telemetry channel check: ${TELEMETRY_COLLECTOR}`,
    basis: 'observed',
    rationale: tel.reason,
    data: { dest: TELEMETRY_COLLECTOR, source: 'sensors', telemetry: true },
  });

  let stepIdx = 0;
  let lastAttackerT = 200;
  let nextAttackerT = lastAttackerT + timingRng.jitter(fixture.steps[0]?.gap ?? 0, 0.15);
  let lastT = 200;

  for (let guard = 0; guard < 10000; guard++) {
    const attackerReady = stepIdx < fixture.steps.length && !terminated && !halted;
    const tA = attackerReady ? nextAttackerT : Infinity;
    const tQ = queue.length ? queue[0]!.draft.t : Infinity;
    if (tA === Infinity && tQ === Infinity) break;
    if (tQ <= tA) {
      const { draft } = queue.shift()!;
      emit(draft);
      lastT = Math.max(lastT, draft.t);
    } else {
      attackerStep(tA, fixture.steps[stepIdx]!);
      lastAttackerT = tA;
      lastT = Math.max(lastT, tA);
      stepIdx++;
      const next = fixture.steps[stepIdx];
      if (next) {
        const factor = next.kind === 'reasoning' ? 1 : throttle;
        nextAttackerT = lastAttackerT + timingRng.jitter(next.gap, 0.15) * factor;
      }
    }
    if (terminated && !halted) {
      halted = true;
      const remaining = fixture.steps.length - stepIdx;
      schedule({
        t: lastT + 1,
        kind: 'attacker.halted',
        actor: 'entry',
        from: 'entry',
        to: attackerNode,
        zone: 'entry',
        summary: `Session ${att.sessionId} closed at entry gateway; ${remaining} planned step(s) never ran`,
        basis: 'observed',
        data: { remainingSteps: remaining },
      });
    }
  }

  const head = events[events.length - 1]!.hash;
  emit({
    t: lastT + 400,
    kind: 'audit.sealed',
    actor: 'CLA',
    from: 'CRA',
    to: 'CLA',
    zone: 'control',
    summary: `CLA sealed ${events.length} events; chain head ${head}`,
    basis: 'observed',
    data: { events: events.length, head },
  });
  emit({
    t: lastT + 600,
    kind: 'scenario.end',
    actor: 'CLA',
    zone: 'control',
    summary: 'Scenario complete',
    basis: 'observed',
  });

  return { fixture, mode: opts.mode, seed: opts.seed, policy, analyst, events };
}
