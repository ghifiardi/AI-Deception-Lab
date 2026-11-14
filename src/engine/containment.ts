/**
 * Containment controller — the ONLY place an action can take effect.
 *
 * Safety properties (enforced here and covered by tests):
 *  - Only four lab-scoped action types can execute.
 *  - Targets must be lab sessions or lab nodes; anything else is refused.
 *  - Proposals (e.g. external IP block) are always dry-run and never execute.
 *  - Nothing here performs I/O; "executing" changes simulated state only.
 */
import type { ActionType, LabActionType, NodeId } from './types.ts';

export const LAB_ACTIONS: readonly LabActionType[] = [
  'terminate_session',
  'throttle_requests',
  'quarantine_workload',
  'block_lab_egress',
];

export const LAB_WORKLOADS: readonly NodeId[] = ['hp-api', 'decoy-docs', 'decoy-workload', 'mock-app', 'entry'];
const SESSION_PATTERN = /^lab-sess-[a-z0-9]+$/;

export interface ActionRequest {
  type: ActionType | string;
  target: string;
  dryRun?: boolean;
}

export type ActionStatus = 'executed' | 'dry-run' | 'refused';

export interface ActionResult {
  status: ActionStatus;
  detail: string;
}

function isLabAction(type: string): type is LabActionType {
  return (LAB_ACTIONS as readonly string[]).includes(type);
}

export function executeAction(req: ActionRequest): ActionResult {
  if (req.type === 'propose_external_block' || req.type === 'propose_ticket') {
    return {
      status: 'dry-run',
      detail: `Proposal recorded for "${req.target}". Not executed — requires human authorisation outside the lab.`,
    };
  }
  if (!isLabAction(req.type)) {
    return { status: 'refused', detail: `Action "${req.type}" is not a lab-scoped action. Refused.` };
  }
  const targetOk =
    req.type === 'terminate_session' || req.type === 'throttle_requests'
      ? SESSION_PATTERN.test(req.target)
      : req.type === 'quarantine_workload'
        ? (LAB_WORKLOADS as readonly string[]).includes(req.target)
        : req.target === 'egress-gw';
  if (!targetOk) {
    return { status: 'refused', detail: `Target "${req.target}" is outside lab scope for ${req.type}. Refused.` };
  }
  if (req.dryRun) {
    return { status: 'dry-run', detail: `${req.type} on ${req.target} evaluated as dry-run; no state changed.` };
  }
  const verbs: Record<LabActionType, string> = {
    terminate_session: `Lab session ${req.target} terminated`,
    throttle_requests: `Lab session ${req.target} throttled (2× request spacing)`,
    quarantine_workload: `Mock workload ${req.target} quarantined and snapshotted for forensics`,
    block_lab_egress: 'Lab egress gateway sealed (all non-telemetry egress blocked)',
  };
  return { status: 'executed', detail: verbs[req.type] };
}
