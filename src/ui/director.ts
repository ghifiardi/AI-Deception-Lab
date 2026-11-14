/**
 * Demo director: a scripted 3–5 minute tour for screen recording.
 * Captions are keyed to real events in the compiled run, so if the engine
 * changes the narration still lines up with what is on screen.
 */
import type { DeceptionMode, EventKind, LabEvent, ScenarioId } from '../engine/types.ts';
import type { CameraRegion } from './topology.ts';

export interface Cue {
  kind: EventKind;
  ruleId?: string;
  action?: string;
  /** Match the nth occurrence (1-based) of this kind. Default 1. */
  nth?: number;
  caption: string;
  camera?: CameraRegion;
}

export type Shot =
  | { type: 'card'; title: string; body: string[]; ms: number }
  | { type: 'tour'; stops: { camera: CameraRegion; caption: string; ms: number }[] }
  | {
      type: 'run';
      scenario: ScenarioId;
      mode: DeceptionMode;
      speed: number;
      cues: Cue[];
      /** Human-in-the-loop demo: the director makes this decision after a pause. */
      analyst?: { ruleId: string; decision: 'approve' | 'reject' | 'observe'; afterMs: number };
    }
  | { type: 'experiments'; caption: string; ms: number }
  | { type: 'compare'; scenario: ScenarioId; mode: DeceptionMode; caption: string; ms: number };

export const DEMO_SEED = 42;

export const DEMO_SHOTS: Shot[] = [
  {
    type: 'card',
    title: 'GATRA Deception Lab',
    body: [
      'A synthetic attacker meets decoys inside an isolated lab.',
      'The scenarios are simulated in this browser. The measured results near the end come from a local mock lab. Nothing touches production.',
    ],
    ms: 9000,
  },
  {
    type: 'tour',
    stops: [
      { camera: 'all', caption: 'Left to right: the simulated internet, a public entry point, then the isolated deception network.', ms: 6500 },
      { camera: 'deception', caption: 'The hatched zone is sealed. Its honeypots and decoy files have no route to production and hold only synthetic data.', ms: 7000 },
      { camera: 'egress', caption: 'Outbound traffic is denied by default. The only allowed path carries sensor telemetry to the lab collector.', ms: 6500 },
      { camera: 'agents', caption: 'Simulated GATRA agent roles assess the evidence. A policy engine decides, and an analyst approves anything uncertain.', ms: 7000 },
    ],
  },
  {
    type: 'run',
    scenario: 'api-canary',
    mode: 'adaptive',
    speed: 0.7,
    cues: [
      { kind: 'scenario.start', caption: 'Scenario 1: a scripted client probes the public API.', camera: 'entry' },
      { kind: 'decoy.response', caption: 'It finds an undocumented endpoint. That endpoint is a honeypot, and nothing legitimate ever calls it.', camera: 'deception' },
      { kind: 'policy.decision', ruleId: 'R-DECOY-01', caption: 'First decoy hit. The session is throttled, a reversible lab-only step, while evidence builds.', camera: 'agents' },
      { kind: 'canary.issued', caption: 'A decoy backup file contains a canary key. It is synthetic and invalid everywhere.', camera: 'deception' },
      { kind: 'canary.used', caption: 'The client tries the key. A canary has no legitimate use, so this is direct evidence.', camera: 'entry' },
      { kind: 'policy.decision', ruleId: 'R-CANARY-01', caption: 'Rule R-CANARY-01 fires automatically: end the session and quarantine the decoy for forensics.', camera: 'agents' },
      { kind: 'containment.result', action: 'propose_external_block', caption: 'Blocking the outside address is only a dry-run proposal. A human must authorise anything beyond the lab.', camera: 'agents' },
      { kind: 'attacker.halted', caption: 'Contained. The export step never ran.', camera: 'all' },
    ],
  },
  {
    type: 'compare',
    scenario: 'api-canary',
    mode: 'adaptive',
    caption: 'Same seed, three modes. Without decoys the client reaches its objective. With decoys it never touches the real target.',
    ms: 13000,
  },
  {
    type: 'run',
    scenario: 'false-positive',
    mode: 'static',
    speed: 0.6,
    analyst: { ruleId: 'R-SAFE-00', decision: 'reject', afterMs: 5500 },
    cues: [
      { kind: 'scenario.start', caption: 'Scenario 2: an approved vulnerability scanner sweeps the estate. This time a human makes the call.', camera: 'entry' },
      { kind: 'decoy.response', caption: 'It touches decoys too, as scanners do.', camera: 'deception' },
      { kind: 'policy.decision', ruleId: 'R-SAFE-00', caption: 'The approved-source safeguard matches first. Automated containment is suppressed.', camera: 'agents' },
      { kind: 'approval.requested', caption: 'Playback stops. The analyst can approve, reject, or keep observing. Here they check the change record and reject.', camera: 'agents' },
      { kind: 'approval.denied', caption: 'The decision is recorded as an event in the SHA-256 chain, so this run replays exactly. The scan finishes undisturbed.', camera: 'all' },
    ],
  },
  {
    type: 'run',
    scenario: 'agentic-decoy',
    mode: 'adaptive',
    speed: 1.4,
    cues: [
      { kind: 'scenario.start', caption: 'Scenario 3: our own red-team agent, instrumented by the lab harness, with hard limits of 24 steps, 40,000 tokens and 90 seconds.', camera: 'all' },
      { kind: 'attacker.reasoning', caption: 'Because we instrumented it, token use is measured, not guessed.', camera: 'entry' },
      { kind: 'decoy.response', nth: 2, caption: 'Adaptive decoys keep offering plausible leads to follow.', camera: 'deception' },
      { kind: 'budget.exhausted', caption: 'The harness stops the agent at its token limit. This is an experiment bound, not a trap.', camera: 'all' },
      { kind: 'containment.result', action: 'terminate_session', caption: 'The lab session is closed and the evidence is sealed in the audit log.', camera: 'agents' },
    ],
  },
  {
    type: 'compare',
    scenario: 'agentic-decoy',
    mode: 'adaptive',
    caption: 'In this fixture, adaptive decoys raised the agent’s tool calls and tokens. That is one measured run testing a hypothesis, not a guarantee.',
    ms: 13000,
  },
  {
    type: 'run',
    scenario: 'egress-block',
    mode: 'adaptive',
    speed: 0.7,
    cues: [
      { kind: 'scenario.start', caption: 'Scenario 4: a client gains a foothold on a decoy workload.', camera: 'deception' },
      { kind: 'egress.attempt', caption: 'It tries to call out to an outside address.', camera: 'egress' },
      { kind: 'egress.denied', nth: 1, caption: 'Default-deny egress. Only the telemetry collector is reachable, so this is denied and logged.', camera: 'egress' },
      { kind: 'policy.decision', ruleId: 'R-EGRESS-01', caption: 'The workload is quarantined and the lab egress gateway is sealed.', camera: 'agents' },
      { kind: 'egress.denied', nth: 3, caption: 'Even a lookalike of the collector’s hostname is denied. Only the exact host and port pass.', camera: 'egress' },
    ],
  },
  {
    type: 'experiments',
    caption: 'Measured: a local cyber-tuned model attacked the lab target with no, static and adaptive deception, under the same seeds and budgets. No commercial API was involved.',
    ms: 12000,
  },
  {
    type: 'experiments',
    caption: 'Outcomes keep success, containment and deception apart. Every difference carries a 95% interval and is labelled exploratory unless pre-registered, adequately powered and clear of zero.',
    ms: 12000,
  },
  {
    type: 'card',
    title: 'What the lab shows',
    body: [
      'Every decision traces back to evidence IDs and a named rule, in a SHA-256 hash chain.',
      'Only lab-scoped actions can run. Anything broader is a dry-run proposal for a human.',
      'Attacker token metrics appear only when the attacker is instrumented.',
      'Local models run with no commercial credentials, no outbound connections, and signed, verifiable records.',
      'Measured lab results and synthetic illustrations are labelled apart. Neither is a production claim.',
    ],
    ms: 12000,
  },
];

/** Returns the cue to fire for this event, tracking per-kind occurrence counts. */
export function matchCue(cues: Cue[], e: LabEvent, counts: Map<string, number>, fired: Set<Cue>): Cue | undefined {
  const n = (counts.get(e.kind) ?? 0) + 1;
  counts.set(e.kind, n);
  return cues.find(
    (c) =>
      !fired.has(c) &&
      c.kind === e.kind &&
      (c.ruleId === undefined || c.ruleId === e.ruleId) &&
      (c.action === undefined || c.action === e.action) &&
      (c.nth === undefined ? c.ruleId !== undefined || c.action !== undefined || n === 1 : c.nth === n),
  );
}
