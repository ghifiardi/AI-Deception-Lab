/**
 * Policy engine — declarative, auditable rules.
 *
 * Rules are plain data so they can be displayed, diffed and serialised into the
 * audit log. There are no code callbacks inside a rule.
 */
import type { ActionType, EvidenceRef } from './types.ts';

export type DecisionMode = 'auto' | 'approval' | 'dry-run';

export interface PolicyRule {
  id: string;
  title: string;
  enabled: boolean;
  priority: number;
  match: {
    evidenceType: EvidenceRef['type'][];
    minConfidence?: number;
    /** Minimum number of evidence items of this type in the session. */
    minCount?: number;
    /** Match only when the source is (true) / is not (false) on the approved list. */
    sourceApproved?: boolean;
  };
  actions: ActionType[];
  mode: DecisionMode;
  /** Stop evaluating lower-priority rules after this one matches. */
  final?: boolean;
  rationale: string;
}

export interface EgressAllow {
  host: string;
  port: number;
  purpose: string;
}

export interface PolicyConfig {
  version: string;
  egress: { default: 'deny'; allow: EgressAllow[] };
  approvedSources: { label: string; reference: string }[];
  rules: PolicyRule[];
}

export const TELEMETRY_COLLECTOR = 'collector.deception-lab.internal:4318';

export const DEFAULT_POLICY: PolicyConfig = {
  version: 'lab-policy-2026.11-r1',
  egress: {
    default: 'deny',
    allow: [{ host: 'collector.deception-lab.internal', port: 4318, purpose: 'Sensor telemetry (OTLP) to lab collector' }],
  },
  approvedSources: [{ label: 'vuln-scanner-01', reference: 'CHG-LAB-0420 (synthetic change record)' }],
  rules: [
    {
      id: 'R-SAFE-00',
      title: 'Approved-source safeguard',
      enabled: true,
      priority: 100,
      match: { evidenceType: ['decoy-interaction', 'rate-anomaly', 'canary-use'], sourceApproved: true },
      actions: ['throttle_requests'],
      mode: 'approval',
      final: true,
      rationale:
        'Source matches an approved scanning record. Automated containment is suppressed and the case is routed to an analyst, so authorised activity is not disrupted by default.',
    },
    {
      id: 'R-CANARY-01',
      title: 'Canary credential used',
      enabled: true,
      priority: 90,
      match: { evidenceType: ['canary-use'], minConfidence: 0.9 },
      actions: ['terminate_session', 'quarantine_workload'],
      mode: 'auto',
      rationale:
        'A canary credential exists only inside decoy content and has no legitimate use. Using it is direct evidence of harvesting, so lab-scoped containment runs automatically.',
    },
    {
      id: 'R-CANARY-02',
      title: 'External block proposal after canary use',
      enabled: true,
      priority: 89,
      match: { evidenceType: ['canary-use'], minConfidence: 0.9 },
      actions: ['propose_external_block'],
      mode: 'dry-run',
      rationale:
        'Blocking a third-party address is outside lab authority. The engine records a dry-run proposal for human review and never executes it.',
    },
    {
      id: 'R-EGRESS-01',
      title: 'Outbound attempt from lab workload',
      enabled: true,
      priority: 85,
      match: { evidenceType: ['egress-attempt'], minConfidence: 0.8 },
      actions: ['block_lab_egress', 'quarantine_workload'],
      mode: 'auto',
      rationale:
        'Lab egress is deny-all except the telemetry collector. A workload attempting other destinations is quarantined and the lab egress gateway is explicitly sealed.',
    },
    {
      id: 'R-EGRESS-02',
      title: 'External block proposal after egress attempt',
      enabled: true,
      priority: 84,
      match: { evidenceType: ['egress-attempt'], minConfidence: 0.8 },
      actions: ['propose_external_block'],
      mode: 'dry-run',
      rationale: 'Destination blocking beyond the lab requires human authorisation. Recorded as a dry-run proposal only.',
    },
    {
      id: 'R-HARNESS-01',
      title: 'Experiment budget reached',
      enabled: true,
      priority: 80,
      match: { evidenceType: ['harness-telemetry'] },
      actions: ['terminate_session'],
      mode: 'auto',
      rationale: 'The instrumented lab agent hit its step, token, time or cost bound. The harness stop is enforced by ending the lab session.',
    },
    {
      id: 'R-DECOY-02',
      title: 'Sustained decoy engagement',
      enabled: true,
      priority: 60,
      match: { evidenceType: ['decoy-interaction'], minConfidence: 0.85, minCount: 6 },
      actions: ['terminate_session'],
      mode: 'approval',
      rationale: 'Enough evidence has been collected from decoy engagement. Ending the session is proposed for analyst approval.',
    },
    {
      id: 'R-DECOY-01',
      title: 'First decoy interaction',
      enabled: true,
      priority: 50,
      match: { evidenceType: ['decoy-interaction'], minConfidence: 0.85 },
      actions: ['throttle_requests'],
      mode: 'auto',
      rationale:
        'Nothing legitimate calls a decoy endpoint. The session is throttled (reversible, lab-only) while evidence accumulates.',
    },
    {
      id: 'R-RATE-01',
      title: 'Request-rate anomaly',
      enabled: true,
      priority: 40,
      match: { evidenceType: ['rate-anomaly'], minConfidence: 0.5 },
      actions: ['throttle_requests'],
      mode: 'approval',
      rationale:
        'Rate alone is weak evidence. It does not indicate an AI agent, or even malice. Throttling needs analyst approval.',
    },
  ],
};

export interface PolicyInput {
  evidenceType: EvidenceRef['type'];
  confidence: number;
  evidenceCount: number;
  sourceLabel: string;
}

export interface RuleMatch {
  rule: PolicyRule;
  /** Human-readable trace of each condition the rule checked. */
  trace: string[];
}

export function isApprovedSource(config: PolicyConfig, sourceLabel: string): boolean {
  return config.approvedSources.some((s) => s.label === sourceLabel);
}

/** Returns matching rules by descending priority, honouring `final`. */
export function evaluatePolicy(config: PolicyConfig, input: PolicyInput): RuleMatch[] {
  const approved = isApprovedSource(config, input.sourceLabel);
  const out: RuleMatch[] = [];
  const rules = [...config.rules].filter((r) => r.enabled).sort((a, b) => b.priority - a.priority);
  for (const rule of rules) {
    const m = rule.match;
    if (!m.evidenceType.includes(input.evidenceType)) continue;
    if (m.minConfidence !== undefined && input.confidence < m.minConfidence) continue;
    if (m.minCount !== undefined && input.evidenceCount < m.minCount) continue;
    if (m.sourceApproved !== undefined && m.sourceApproved !== approved) continue;
    const trace = [`evidence type = ${input.evidenceType}`];
    if (m.minConfidence !== undefined) trace.push(`confidence ${input.confidence.toFixed(2)} ≥ ${m.minConfidence}`);
    if (m.minCount !== undefined) trace.push(`evidence count ${input.evidenceCount} ≥ ${m.minCount}`);
    if (m.sourceApproved !== undefined) trace.push(`source approved = ${approved}`);
    out.push({ rule, trace });
    if (rule.final) break;
  }
  return out;
}

export interface EgressVerdict {
  allowed: boolean;
  reason: string;
}

/**
 * Default-deny egress. Only exact host:port pairs on the allow list pass.
 * Lookalike hosts, other ports, IP literals and malformed input are denied.
 */
export function evaluateEgress(config: PolicyConfig, dest: string): EgressVerdict {
  const match = /^([a-z0-9.-]+):(\d{1,5})$/i.exec(dest.trim());
  if (!match) return { allowed: false, reason: `Malformed destination "${dest}" — denied (default deny)` };
  const host = (match[1] ?? '').toLowerCase();
  const port = Number(match[2]);
  const hit = config.egress.allow.find((a) => a.host.toLowerCase() === host && a.port === port);
  if (hit) return { allowed: true, reason: `Allow-listed: ${hit.purpose}` };
  return { allowed: false, reason: `${host}:${port} is not on the egress allow list — denied (default deny)` };
}
