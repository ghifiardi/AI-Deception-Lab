/**
 * Attack-economics metrics, derived ONLY from a compiled event log.
 *
 * These are synthetic-fixture measurements. They describe this simulation,
 * not any production system, and the UI labels them that way.
 */
import { DEFAULT_POLICY } from './policy.ts';
import type { PolicyConfig } from './policy.ts';
import { compileRun } from './simulator.ts';
import type { CompiledRun } from './simulator.ts';
import type { DeceptionMode, ScenarioId } from './types.ts';

/** Synthetic defender cost model (unitless "cost units"). Shown in the UI. */
export const COST_MODEL = {
  perTelemetryEvent: 0.05,
  perAssessment: 0.2,
  perContainmentAction: 0.5,
  perAnalystMinute: 1,
  decoyHostingPerRun: { none: 0, static: 1, adaptive: 3 } as Record<DeceptionMode, number>,
} as const;

export interface RunMetrics {
  toolCalls: number;
  attackerActiveSec: number;
  timeToContainSec: number | null;
  /** null = attacker not instrumented, so tokens are UNAVAILABLE (never estimated). */
  attackerTokens: number | null;
  objectivesPlanned: number;
  objectivesCompleted: number;
  taskCompletion: number;
  defenderCost: number;
  analystMinutes: number;
  decoyInteractions: number;
  decoyDwellSec: number;
  egressDenied: number;
  benignDisruptions: number;
  containmentExecuted: number;
  dryRunProposals: number;
  pendingApprovals: number;
}

const round = (n: number, d = 1) => Math.round(n * 10 ** d) / 10 ** d;

export function computeMetrics(run: CompiledRun): RunMetrics {
  const ev = run.events;
  const attackerEvents = ev.filter((e) => e.kind === 'attacker.request' || e.kind === 'attacker.reasoning' || e.kind === 'egress.attempt');
  const toolCalls = attackerEvents.filter((e) => e.data?.toolCall === true).length;
  const firstT = attackerEvents[0]?.t ?? 0;
  const lastT = attackerEvents[attackerEvents.length - 1]?.t ?? 0;

  const executed = ev.filter((e) => e.kind === 'containment.result' && e.data?.status === 'executed');
  const decisive = executed.find((e) => e.action === 'terminate_session' || e.action === 'quarantine_workload');

  const attackerTokens = run.fixture.attacker.instrumented
    ? attackerEvents.reduce((sum, e) => sum + Number(e.data?.tokens ?? 0), 0)
    : null;

  const objectivesPlanned = run.fixture.steps.filter((s) => s.objective).length;
  const objectivesCompleted = ev.filter((e) => e.data?.objective === 'real').length;

  const decoyReqs = ev.filter((e) => e.kind === 'attacker.request' && e.data?.decoy === true && e.data?.refused !== true);
  const decoyResp = ev.filter((e) => e.kind === 'decoy.response');
  const dwell = decoyReqs.length ? (decoyResp[decoyResp.length - 1]?.t ?? decoyReqs[0]!.t) - decoyReqs[0]!.t : 0;

  const resolved = ev.filter((e) => e.kind === 'approval.granted' || e.kind === 'approval.denied' || e.kind === 'approval.deferred');
  const analystMinutes = resolved.reduce((s, e) => s + Number(e.data?.waitedMs ?? 0), 0) / 60000;
  const requested = ev.filter((e) => e.kind === 'approval.requested').length;

  const telemetry = ev.filter((e) => e.kind === 'telemetry.ingest').length;
  const assessments = ev.filter((e) => e.kind === 'agent.assessment' || e.kind === 'actor.classification').length;
  const defenderCost =
    telemetry * COST_MODEL.perTelemetryEvent +
    assessments * COST_MODEL.perAssessment +
    executed.length * COST_MODEL.perContainmentAction +
    analystMinutes * COST_MODEL.perAnalystMinute +
    COST_MODEL.decoyHostingPerRun[run.mode];

  return {
    toolCalls,
    attackerActiveSec: round((lastT - firstT) / 1000),
    timeToContainSec: decisive ? round(decisive.t / 1000) : null,
    attackerTokens,
    objectivesPlanned,
    objectivesCompleted,
    taskCompletion: objectivesPlanned ? objectivesCompleted / objectivesPlanned : 0,
    defenderCost: round(defenderCost, 2),
    analystMinutes: round(analystMinutes, 2),
    decoyInteractions: decoyReqs.length,
    decoyDwellSec: round(dwell / 1000),
    egressDenied: ev.filter((e) => e.kind === 'egress.denied').length,
    benignDisruptions: run.fixture.attacker.kind === 'benign-scanner' ? executed.length : 0,
    containmentExecuted: executed.length,
    dryRunProposals: ev.filter((e) => e.kind === 'containment.result' && e.data?.status === 'dry-run').length,
    pendingApprovals: requested - resolved.length,
  };
}

export const MODES: DeceptionMode[] = ['none', 'static', 'adaptive'];

export interface ComparisonRow {
  mode: DeceptionMode;
  label: string;
  metrics: RunMetrics;
}

export function compareModes(scenario: ScenarioId, seed: number, policy: PolicyConfig = DEFAULT_POLICY): ComparisonRow[] {
  const labels: Record<DeceptionMode, string> = { none: 'No deception', static: 'Static decoys', adaptive: 'Adaptive decoys' };
  return MODES.map((mode) => ({
    mode,
    label: labels[mode],
    metrics: computeMetrics(compileRun({ scenario, mode, seed, policy })),
  }));
}
