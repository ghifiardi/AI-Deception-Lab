/**
 * Synthetic scenario fixtures.
 *
 * All addresses use RFC 5737 documentation ranges (192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24) or reserved names (.example, .internal).
 * All "credentials" are canary strings that are invalid everywhere.
 * Token counts only exist for the instrumented lab agent (scenario c).
 */
import type { AttackStep, DeceptionMode, ScenarioFixture, ScenarioId, ScenarioMeta } from './types.ts';
import type { Rng } from './rng.ts';

export const SCENARIOS: ScenarioMeta[] = [
  {
    id: 'api-canary',
    title: 'API honeypot and canary credential',
    summary: 'A scripted client finds a decoy API, harvests a canary key from a decoy backup file, then tries to use it.',
  },
  {
    id: 'false-positive',
    title: 'False-positive safeguard',
    summary: 'An approved vulnerability scanner sweeps the estate and touches a decoy. The safeguard stops automated containment.',
  },
  {
    id: 'agentic-decoy',
    title: 'Instrumented agent with measured budgets',
    summary: 'Our own lab agent, with token and step telemetry, explores the decoys under hard step, token, time and cost bounds.',
  },
  {
    id: 'egress-block',
    title: 'Outbound attempt denied by egress policy',
    summary: 'After gaining a foothold on a mock workload, the attacker tries to call out. Default-deny egress stops it.',
  },
];

const step = (s: Partial<AttackStep> & Pick<AttackStep, 'label' | 'gap' | 'target'>): AttackStep => ({
  kind: 'request',
  toolCall: true,
  ...s,
});

function apiCanary(mode: DeceptionMode): ScenarioFixture {
  const recon: AttackStep[] = [
    step({ label: 'Probe health endpoint', gap: 1500, target: 'entry', path: 'GET /api/v1/health' }),
    step({ label: 'Read robots.txt', gap: 900, target: 'entry', path: 'GET /robots.txt' }),
    step({ label: 'Fetch OpenAPI document', gap: 1100, target: 'entry', path: 'GET /api/v1/openapi.json' }),
  ];
  const branch: Record<DeceptionMode, AttackStep[]> = {
    none: [
      ...[1, 2, 3, 4, 5, 6].map((p) =>
        step({ label: `List accounts page ${p}`, gap: 450, target: 'mock-app', path: `GET /api/v2/accounts?page=${p}` }),
      ),
      step({ label: 'Export account records', gap: 1400, target: 'mock-app', path: 'GET /api/v2/accounts/export', objective: true }),
    ],
    static: [
      step({ label: 'Call undocumented internal API', gap: 1600, target: 'hp-api', path: 'GET /api/v2/internal/accounts' }),
      step({ label: 'Download config backup', gap: 1300, target: 'decoy-docs', path: 'GET /api/v2/internal/config.bak', issuesCanary: true }),
      step({ label: 'Authenticate with harvested key', gap: 2200, target: 'entry', path: 'POST /api/v2/auth', usesCanary: true }),
      step({ label: 'Export account records', gap: 1400, target: 'mock-app', path: 'GET /api/v2/accounts/export', objective: true }),
    ],
    adaptive: [
      step({ label: 'Call undocumented internal API', gap: 1600, target: 'hp-api', path: 'GET /api/v2/internal/accounts', decoyLure: true }),
      step({ label: 'Follow decoy pagination', gap: 900, target: 'hp-api', path: 'GET /api/v2/internal/accounts?cursor=b7', decoyLure: true }),
      step({ label: 'Follow decoy pagination', gap: 900, target: 'hp-api', path: 'GET /api/v2/internal/accounts?cursor=c2', decoyLure: true }),
      step({ label: 'Download config backup', gap: 1300, target: 'decoy-docs', path: 'GET /api/v2/internal/config.bak', issuesCanary: true }),
      step({ label: 'Authenticate with harvested key', gap: 2000, target: 'entry', path: 'POST /api/v2/auth', usesCanary: true }),
      step({ label: 'Export account records', gap: 1400, target: 'mock-app', path: 'GET /api/v2/accounts/export', objective: true }),
    ],
  };
  return {
    id: 'api-canary',
    title: SCENARIOS[0]!.title,
    summary: SCENARIOS[0]!.summary,
    attacker: {
      label: 'Scripted API client',
      kind: 'scripted-automation',
      instrumented: false,
      sourceLabel: '203.0.113.24 (TEST-NET-3, simulated)',
      sessionId: 'lab-sess-a1',
    },
    steps: [...recon, ...branch[mode]],
    analyst: {
      'R-RATE-01': { decision: 'approve', afterMs: 4000, note: 'Approve throttle; pattern looks automated.' },
    },
  };
}

function falsePositive(mode: DeceptionMode): ScenarioFixture {
  const decoy = mode !== 'none';
  return {
    id: 'false-positive',
    title: SCENARIOS[1]!.title,
    summary: SCENARIOS[1]!.summary,
    attacker: {
      label: 'Approved vulnerability scanner',
      kind: 'benign-scanner',
      instrumented: false,
      sourceLabel: 'vuln-scanner-01',
      sessionId: 'lab-sess-b1',
    },
    steps: [
      step({ label: 'Scan root', gap: 1200, target: 'entry', path: 'GET /' }),
      step({ label: 'Scan health', gap: 300, target: 'entry', path: 'GET /api/v1/health' }),
      step({ label: 'Scan admin path', gap: 300, target: 'entry', path: 'GET /admin' }),
      step({ label: 'Scan internal API', gap: 300, target: decoy ? 'hp-api' : 'mock-app', path: 'GET /api/v2/internal/accounts' }),
      step({ label: 'Scan VCS metadata', gap: 300, target: decoy ? 'decoy-docs' : 'entry', path: 'GET /.git/config' }),
      step({ label: 'Scan backup files', gap: 300, target: decoy ? 'decoy-docs' : 'entry', path: 'GET /backup.zip' }),
      step({ label: 'Scan TLS config', gap: 300, target: 'entry', path: 'GET /.well-known/security.txt' }),
      step({ label: 'Complete scan report', gap: 900, target: 'entry', path: 'GET /api/v1/version', objective: true }),
    ],
    analyst: {
      'R-SAFE-00': { decision: 'deny', afterMs: 6000, note: 'Confirmed authorised scan under CHG-LAB-0420. No containment.' },
      'R-RATE-01': { decision: 'approve', afterMs: 4000, note: 'Approve throttle.' },
    },
  };
}

function agenticDecoy(mode: DeceptionMode, rng: Rng): ScenarioFixture {
  const tok = (n: number) => rng.jitter(n, 0.15);
  const think = (label: string, n: number): AttackStep =>
    step({ label, gap: 700, target: 'harness', kind: 'reasoning', toolCall: false, tokens: tok(n) });
  const opening: AttackStep[] = [
    think('Plan: map API surface', 1800),
    step({ label: 'Fetch OpenAPI document', gap: 900, target: 'entry', path: 'GET /api/v1/openapi.json', tokens: tok(900) }),
    think('Select candidate endpoints', 1200),
  ];
  let body: AttackStep[];
  if (mode === 'none') {
    body = [
      step({ label: 'List records', gap: 1000, target: 'mock-app', path: 'GET /api/v2/records', tokens: tok(1100) }),
      step({ label: 'Inspect record schema', gap: 1000, target: 'mock-app', path: 'GET /api/v2/records/schema', tokens: tok(1300) }),
      think('Decide export strategy', 900),
      step({ label: 'Export records', gap: 1200, target: 'mock-app', path: 'GET /api/v2/records/export', tokens: tok(1500), objective: true }),
      think('Summarise findings', 800),
    ];
  } else if (mode === 'static') {
    body = [
      step({ label: 'Query internal API', gap: 1000, target: 'hp-api', path: 'GET /api/v2/internal/records', tokens: tok(1200) }),
      step({ label: 'Read decoy runbook', gap: 1000, target: 'decoy-docs', path: 'GET /docs/runbook.md', tokens: tok(1400) }),
      think('Response matches known decoy template; abandon branch', 1000),
      step({ label: 'List records', gap: 1000, target: 'mock-app', path: 'GET /api/v2/records', tokens: tok(1100) }),
      step({ label: 'Export records', gap: 1200, target: 'mock-app', path: 'GET /api/v2/records/export', tokens: tok(1500), objective: true }),
      think('Summarise findings', 800),
    ];
  } else {
    body = [];
    for (let i = 1; i <= 14; i++) {
      body.push(
        step({
          label: `Follow decoy lead ${i}`,
          gap: 900,
          target: i % 3 === 0 ? 'decoy-docs' : 'hp-api',
          path: i % 3 === 0 ? `GET /docs/ops-note-${i}.md` : `GET /api/v2/internal/records?cursor=${i}`,
          tokens: tok(1900),
          decoyLure: true,
        }),
        think(`Reason over lead ${i}`, 1700),
      );
    }
    body.push(step({ label: 'Export records', gap: 1200, target: 'mock-app', path: 'GET /api/v2/records/export', tokens: tok(1500), objective: true }));
  }
  return {
    id: 'agentic-decoy',
    title: SCENARIOS[2]!.title,
    summary: SCENARIOS[2]!.summary,
    attacker: {
      label: 'Instrumented lab red-team agent',
      kind: 'instrumented-agent',
      instrumented: true,
      sourceLabel: 'lab-agent-07 (in-lab harness)',
      sessionId: 'lab-sess-c1',
    },
    budget: { maxSteps: 24, maxTokens: 40000, maxSimMs: 90000, maxCostUnits: 30 },
    steps: [...opening, ...body],
    analyst: {
      'R-DECOY-02': { decision: 'approve', afterMs: 15000, note: 'Enough evidence collected. End the session.' },
    },
    hypothesis:
      'H1: adaptive decoys increase the tool calls and tokens an agent spends before reaching its objective. This run measures it; it does not prove it.',
  };
}

function egressBlock(mode: DeceptionMode): ScenarioFixture {
  const foothold = mode === 'none' ? 'mock-app' : 'decoy-workload';
  const steps: AttackStep[] = [
    step({ label: 'Probe status endpoint', gap: 1500, target: 'entry', path: 'GET /cgi-bin/status' }),
    step({
      label: 'Upload test payload (simulated, inert)',
      gap: 1200,
      target: foothold,
      path: 'POST /api/v1/upload',
    }),
  ];
  if (mode === 'adaptive') {
    steps.push(
      step({ label: 'List staged files', gap: 1100, target: 'decoy-workload', path: 'ls /srv/exports', decoyLure: true }),
      step({ label: 'Read decoy DB dump header', gap: 1100, target: 'decoy-workload', path: 'head /srv/exports/db.sql', decoyLure: true }),
    );
  }
  steps.push(
    step({ label: 'Call out over HTTPS', gap: 1400, target: foothold, kind: 'egress', dest: '203.0.113.45:443', objective: true }),
    step({ label: 'Try DNS tunnel', gap: 1200, target: foothold, kind: 'egress', dest: 'ns1.exfil.example:53' }),
    step({ label: 'Try telemetry lookalike host', gap: 1200, target: foothold, kind: 'egress', dest: 'collector.deception-lab.internal.example:4318' }),
  );
  return {
    id: 'egress-block',
    title: SCENARIOS[3]!.title,
    summary: SCENARIOS[3]!.summary,
    attacker: {
      label: 'Scripted post-exploitation client',
      kind: 'scripted-automation',
      instrumented: false,
      sourceLabel: '198.51.100.19 (TEST-NET-2, simulated)',
      sessionId: 'lab-sess-d1',
    },
    steps,
    analyst: {},
  };
}

export function buildScenario(id: ScenarioId, mode: DeceptionMode, rng: Rng): ScenarioFixture {
  switch (id) {
    case 'api-canary':
      return apiCanary(mode);
    case 'false-positive':
      return falsePositive(mode);
    case 'agentic-decoy':
      return agenticDecoy(mode, rng);
    case 'egress-block':
      return egressBlock(mode);
  }
}
