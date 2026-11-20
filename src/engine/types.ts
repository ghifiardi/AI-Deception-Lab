/**
 * GATRA Deception Lab — event schema.
 *
 * Everything in this module describes a SIMULATED lab. No type here maps to a
 * live system, credential, or network endpoint.
 */

export type ScenarioId = 'api-canary' | 'false-positive' | 'agentic-decoy' | 'egress-block' | 'swarm-v2';
export type DeceptionMode = 'none' | 'static' | 'adaptive';

/** Topology nodes rendered by the UI and referenced by events. */
export type NodeId =
  | 'attacker'
  | 'scanner'
  /** Legitimate swarm clients (Defense V2 runs only). */
  | 'legit'
  | 'entry'
  | 'mock-app'
  | 'hp-api'
  | 'decoy-docs'
  | 'decoy-workload'
  | 'collector'
  | 'egress-gw'
  | 'internet-out'
  | 'ADA'
  | 'TAA'
  | 'policy'
  | 'analyst'
  | 'CRA'
  | 'CLA'
  | 'harness';

export type Zone =
  | 'internet'
  | 'entry'
  | 'mock-target'
  | 'deception'
  | 'telemetry'
  | 'analysis'
  | 'control'
  | 'egress';

export type EventKind =
  | 'scenario.start'
  | 'attacker.request'
  | 'attacker.reasoning'
  | 'attacker.halted'
  | 'decoy.response'
  | 'canary.issued'
  | 'canary.used'
  | 'egress.attempt'
  | 'egress.allowed'
  | 'egress.denied'
  | 'telemetry.ingest'
  | 'agent.assessment'
  | 'actor.classification'
  | 'policy.decision'
  | 'approval.requested'
  | 'approval.granted'
  | 'approval.denied'
  | 'approval.deferred'
  | 'containment.action'
  | 'containment.result'
  | 'budget.exhausted'
  | 'audit.sealed'
  | 'agent.outcome'
  | 'scenario.end';

/**
 * observed  = directly recorded by a lab sensor (fact about the lab).
 * inferred  = an interpretation produced by an assessment step (may be wrong).
 */
export type Basis = 'observed' | 'inferred';

export type ApprovalState = 'not-required' | 'pending' | 'approved' | 'denied' | 'deferred';

/** Lab-scoped containment actions. Nothing outside the lab is representable. */
export type LabActionType =
  | 'terminate_session'
  | 'throttle_requests'
  | 'quarantine_workload'
  | 'block_lab_egress';

/** Broader responses can only ever exist as dry-run proposals. */
export type ProposalType = 'propose_external_block' | 'propose_ticket';

export type ActionType = LabActionType | ProposalType;

export interface EvidenceRef {
  id: string;
  type:
    | 'decoy-interaction'
    | 'canary-use'
    | 'rate-anomaly'
    | 'egress-attempt'
    | 'harness-telemetry'
    | 'allowlist-match';
  observed: string[];
}

export interface LabEvent {
  seq: number;
  id: string;
  /** Simulated milliseconds since scenario start (never wall-clock). */
  t: number;
  kind: EventKind;
  actor: NodeId;
  from?: NodeId;
  to?: NodeId;
  zone: Zone;
  summary: string;
  basis: Basis;
  /** 0..1, present for inferred judgements. */
  confidence?: number;
  evidence?: EvidenceRef;
  /** Inferred statements attached to an assessment. */
  inferred?: string[];
  ruleId?: string;
  rationale?: string;
  approval?: ApprovalState;
  action?: ActionType;
  dryRun?: boolean;
  data?: Record<string, string | number | boolean | null>;
  prevHash: string;
  hash: string;
}

/** An event before sequencing and hashing. */
export type DraftEvent = Omit<LabEvent, 'seq' | 'id' | 'prevHash' | 'hash'>;

/* ------------------------------------------------------------------ */
/* Scenario fixtures                                                    */
/* ------------------------------------------------------------------ */

export interface AttackerProfile {
  label: string;
  /** Who is acting: scripted tool, instrumented lab agent, or benign source. */
  kind: 'scripted-automation' | 'instrumented-agent' | 'benign-scanner';
  /** True only when OUR lab harness reports the attacker's token usage. */
  instrumented: boolean;
  sourceLabel: string;
  sessionId: string;
}

export interface Budget {
  maxSteps: number;
  maxTokens: number;
  maxSimMs: number;
  maxCostUnits: number;
}

export interface AttackStep {
  label: string;
  /** Simulated ms after the previous attacker step. */
  gap: number;
  kind: 'request' | 'reasoning' | 'egress';
  /** Destination node in the lab topology. */
  target: NodeId;
  path?: string;
  /** For egress: destination host:port (documentation ranges only). */
  dest?: string;
  /** Tool call by the attacker (counted in metrics). */
  toolCall: boolean;
  /** Tokens reported by the harness (only meaningful if instrumented). */
  tokens?: number;
  /** Uses the canary credential issued earlier. */
  usesCanary?: boolean;
  /** Request returns a canary credential. */
  issuesCanary?: boolean;
  /** Completing this step against a real (mock) target = objective achieved. */
  objective?: boolean;
  /** Decoy produced extra content for the attacker to chase. */
  decoyLure?: boolean;
}

export interface AnalystScript {
  /** ruleId -> scripted analyst response. */
  [ruleId: string]: { decision: 'approve' | 'deny'; afterMs: number; note: string };
}

export interface ScenarioFixture {
  id: ScenarioId;
  title: string;
  summary: string;
  attacker: AttackerProfile;
  budget?: Budget;
  steps: AttackStep[];
  analyst: AnalystScript;
  hypothesis?: string;
}

export interface ScenarioMeta {
  id: ScenarioId;
  title: string;
  summary: string;
}

/* ------------------------------------------------------------------ */
/* Human-in-the-loop analyst                                            */
/* ------------------------------------------------------------------ */

/**
 * approve  = run the rule's lab actions.
 * reject   = do not act; the case is closed for this rule.
 * observe  = do not act yet; keep watching. The rule may ask again when new
 *            matching evidence arrives.
 */
export type AnalystDecision = 'approve' | 'reject' | 'observe';

/** One recorded human decision. Inputs are part of a run's configuration, so replays are exact. */
export interface AnalystInput {
  ruleId: string;
  decision: AnalystDecision;
  /** Simulated ms at which the analyst decided (must be at or after the request). */
  atT: number;
  note?: string;
}

export type AnalystConfig = { mode: 'scripted' } | { mode: 'interactive'; inputs: AnalystInput[] };
