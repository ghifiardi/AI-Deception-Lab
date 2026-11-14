/**
 * Derives the visible lab state from the first `count` events of a run.
 * Pure function: the UI never mutates state directly, so stepping backwards,
 * seeking and resetting are all just "derive at a different cursor".
 */
import type { CompiledRun } from './simulator.ts';
import type { ApprovalState, LabEvent, NodeId } from './types.ts';

export type NodeStatus = 'idle' | 'active' | 'alert' | 'quarantined' | 'sealed' | 'terminated';
export type SessionStatus =
  | 'not-started'
  | 'active'
  | 'throttled'
  | 'workload-contained'
  | 'terminated'
  | 'stopped-by-harness'
  | 'finished';

export interface DecisionView {
  decision: LabEvent;
  approval: ApprovalState;
  approvalNote?: string;
  results: LabEvent[];
}

export interface ViewState {
  count: number;
  t: number;
  last?: LabEvent;
  nodes: Partial<Record<NodeId, NodeStatus>>;
  session: SessionStatus;
  assessment?: LabEvent;
  classification?: LabEvent;
  decisions: DecisionView[];
  egressDenied: LabEvent[];
  tokens: number | null;
  toolCalls: number;
  canaryIssued?: string;
  canaryUsed: boolean;
  ended: boolean;
}

export function deriveState(run: CompiledRun, count: number): ViewState {
  const evs = run.events.slice(0, Math.max(0, Math.min(count, run.events.length)));
  const nodes: Partial<Record<NodeId, NodeStatus>> = {};
  const decisions = new Map<string, DecisionView>();
  const s: ViewState = {
    count: evs.length,
    t: evs[evs.length - 1]?.t ?? 0,
    last: evs[evs.length - 1],
    nodes,
    session: 'not-started',
    decisions: [],
    egressDenied: [],
    tokens: run.fixture.attacker.instrumented ? 0 : null,
    toolCalls: 0,
    canaryUsed: false,
    ended: false,
  };

  for (const e of evs) {
    switch (e.kind) {
      case 'attacker.request':
      case 'attacker.reasoning':
      case 'egress.attempt':
        if (s.session === 'not-started') s.session = 'active';
        if (e.data?.toolCall) s.toolCalls++;
        if (s.tokens !== null) s.tokens += Number(e.data?.tokens ?? 0);
        if (e.to && e.kind === 'attacker.request' && nodes[e.to] !== 'quarantined') nodes[e.to] = 'active';
        break;
      case 'decoy.response':
        if (nodes[e.actor] !== 'quarantined') nodes[e.actor] = 'alert';
        break;
      case 'canary.issued':
        s.canaryIssued = String(e.data?.canaryId);
        break;
      case 'canary.used':
        s.canaryUsed = true;
        nodes[e.actor] = 'alert';
        break;
      case 'egress.denied':
        s.egressDenied.push(e);
        break;
      case 'agent.assessment':
        s.assessment = e;
        break;
      case 'actor.classification':
        s.classification = e;
        break;
      case 'policy.decision':
        decisions.set(e.ruleId!, { decision: e, approval: e.approval ?? 'not-required', results: [] });
        break;
      case 'approval.granted':
      case 'approval.denied':
      case 'approval.deferred': {
        const d = decisions.get(e.ruleId!);
        if (d) {
          d.approval = e.approval!;
          d.approvalNote = e.rationale;
        }
        break;
      }
      case 'containment.result': {
        decisions.get(e.ruleId!)?.results.push(e);
        if (e.data?.status !== 'executed') break;
        const target = String(e.data?.target) as NodeId;
        if (e.action === 'quarantine_workload') {
          nodes[target] = 'quarantined';
          if (s.session === 'active' || s.session === 'throttled') s.session = 'workload-contained';
        }
        if (e.action === 'block_lab_egress') nodes['egress-gw'] = 'sealed';
        if (e.action === 'throttle_requests' && s.session === 'active') s.session = 'throttled';
        if (e.action === 'terminate_session') s.session = 'terminated';
        break;
      }
      case 'budget.exhausted':
        s.session = 'stopped-by-harness';
        break;
      case 'scenario.end':
        s.ended = true;
        if (s.session === 'active' || s.session === 'throttled') s.session = 'finished';
        break;
      default:
        break;
    }
  }
  if (s.session === 'terminated' || s.session === 'stopped-by-harness') {
    nodes[run.fixture.attacker.kind === 'benign-scanner' ? 'scanner' : 'attacker'] = 'terminated';
  }
  s.decisions = [...decisions.values()];
  return s;
}
