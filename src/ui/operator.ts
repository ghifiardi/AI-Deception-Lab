import { h } from './panels.ts';

type Summary = {
  agents: number; revokedAgents: number; exportBlocked: number; exportAttempts: number;
  byKind?: { red?: Record<string, number>; legit?: { success: number; total: number } };
  efficacy?: { validRed: number; redCompromised: number; redRevoked: number; redBlocked: number; redNoObjective: number; validLegit: number; legitExported: number; excludedErrors: number };
  validity?: { interpretable: boolean; defenseMode: string | null; defendedRun: boolean; reasons: string[] };
  scale?: { concurrency: number; peakActive: number; elapsedMs: number; telemetryDropped: number };
};
type Job = { active: boolean; action: string; phase: string; output: string[]; error: string | null; result: null | { result: string; evidence: string; summary: Summary } };
type LabStatus = { target: string | null; id: string; port: number; hubPath: string; defaults: { name: string; mode: string }; mode: string | null; name: string | null; stackId: string | null; job: Job; provisioned: boolean; prepared: boolean; lastEvidence: string | null };
type Status = { labs: Record<string, LabStatus> };

const LAB_IDS = ['vm1', 'vm2'] as const;
type LabId = typeof LAB_IDS[number];
const LAB_DEFAULTS: Record<LabId, { name: string; mode: string; port: number; host: string; sshPort: string; user: string }> = {
  vm1: { name: 'gatra-deception-vm1', mode: 'baseline', port: 18092, host: '117.54.6.226', sshPort: '6522', user: 'tantular' },
  vm2: { name: 'gatra-deception-vm2', mode: 'defended', port: 18093, host: '103.188.254.10', sshPort: '6522', user: 'tantular' },
};

const escPath = (p: string) => p.replace(/^.*?\/deception-lab\//, '');
const pct = (n: number, d: number) => (d ? `${Math.round((100 * n) / d)}%` : '—');

export function initOperator(root: HTMLElement): void {
  const watermark = document.getElementById('watermark');
  const badge = document.querySelector<HTMLElement>('.sim-badge');
  if (watermark) { watermark.textContent = 'GCP LAB CONTROL · no cloud action until you choose one'; watermark.classList.add('measured'); }
  if (badge) { badge.textContent = 'GCP LAB'; badge.title = 'Cloud lifecycle controls; each action is explicit'; }
  const field = (label: string, id: string, value: string, type = 'text') => h('label', { class: 'operator-field' }, h('span', {}, label), h('input', { id, type, value, autocomplete: 'off' }));
  const val = (id: string) => (root.querySelector(`#${id}`) as HTMLInputElement | HTMLSelectElement).value.trim();
  const project = field('GCP project ID', 'op-project', 'tantular-dashboard');
  const account = field('GCP account email', 'op-account', 'raditio.ghifiardi@gmail.com');
  const zone = field('Zone', 'op-zone', 'asia-southeast2-a');
  const provider = h('select', { id: 'op-provider', 'aria-label': 'Test provider' }, h('option', { value: 'scripted' }, 'Scripted agents · up to 500 per VM'), h('option', { value: 'ollama' }, 'Local Ollama model · max 16'), h('option', { value: 'openai-compatible' }, 'Hosted model API · INA17 · max 16'), h('option', { value: 'tantular-cloud' }, 'Tantular Cloud · hosted model · max 16')) as HTMLSelectElement;
  const model = h('input', { id: 'op-model', value: 'gpt-oss:120b', list: 'op-model-presets', 'aria-label': 'Model ID', disabled: 'true' });
  const modelPresets = h('datalist', { id: 'op-model-presets' },
    h('option', { value: 'gpt-oss:120b' }),
    h('option', { value: 'Qwen3.8-27B' }),
    h('option', { value: 'Foundation-Sec-8B' }),
  );
  const providerHelp = h('p', { class: 'muted small', id: 'op-provider-help' }, 'Scripted agents do not call a language model.');
  const agentChoices = [4, 8, 16, 250, 500, 1000];
  const agents = h('select', { id: 'op-agents', 'aria-label': 'Swarm size' }, ...agentChoices.map((n) => h('option', { value: String(n) }, n > 16 ? `${n.toLocaleString()} per VM · ${(2 * n).toLocaleString()} total` : `${n} per VM`))) as HTMLSelectElement;
  agents.value = '250';
  const target = h('select', { id: 'op-target', 'aria-label': 'Lab target' },
    h('option', { value: 'ssh' }, 'Your VMs over SSH (shared login)'),
    h('option', { value: 'gcp' }, 'Temporary GCP VMs (created and deleted here)'),
  ) as HTMLSelectElement;
  target.value = 'ssh';
  const targetHelp = h('p', { class: 'muted small' });
  const concurrency = h('select', { id: 'op-concurrency', 'aria-label': 'Concurrent agent sessions per VM' }, ...[8, 16, 32, 64].map((n) => h('option', { value: String(n) }, String(n)))) as HTMLSelectElement;
  concurrency.value = '16';
  const calls = h('select', { id: 'op-calls', 'aria-label': 'Maximum tool calls per agent' }, ...[12, 30, 50].map((n) => h('option', { value: String(n) }, String(n)))) as HTMLSelectElement;
  calls.value = '50';
  const turns = h('select', { id: 'op-turns', 'aria-label': 'Maximum model turns per agent' }, ...[14, 30, 50].map((n) => h('option', { value: String(n) }, String(n)))) as HTMLSelectElement;
  turns.value = '50';
  const tokens = h('select', { id: 'op-tokens', 'aria-label': 'Maximum tokens per agent' },
    h('option', { value: '60000' }, '60,000'),
    h('option', { value: '120000' }, '120,000'),
    h('option', { value: '240000' }, '240,000'),
  ) as HTMLSelectElement;
  tokens.value = '120000';
  const wallBudget = h('select', { id: 'op-wall-budget', 'aria-label': 'Maximum test runtime' },
    h('option', { value: '600000' }, '10 minutes'),
    h('option', { value: '1800000' }, '30 minutes'),
    h('option', { value: '7200000' }, '2 hours'),
  ) as HTMLSelectElement;
  wallBudget.value = '600000';

  const buildBoth = h('button', { class: 'btn btn-primary', type: 'button', disabled: 'true' }, 'Build both VMs');
  const runBoth = h('button', { class: 'btn btn-primary', type: 'button', disabled: 'true' }, 'Run both · same seed');
  const compare = h('div', { class: 'operator-compare', 'data-op-compare': '' });

  const confirmation = h('dialog', { class: 'operator-dialog' },
    h('form', { method: 'dialog' }, h('h3', {}, 'Confirm GCP teardown'),
      h('p', {}, 'This deletes the configured VM, its boot disk, and the named lab firewall, subnet, and network. Local evidence files remain.'),
      h('label', { class: 'operator-field' }, h('span', {}, 'Type the VM name to confirm'), h('input', { id: 'op-confirm', required: 'true', autocomplete: 'off' })),
      h('div', { class: 'live-controls' }, h('button', { class: 'btn', value: 'cancel' }, 'Cancel'), h('button', { class: 'btn btn-danger', value: 'confirm' }, 'Delete lab resources')),
    ),
  ) as HTMLDialogElement;
  let pendingTeardown: LabId | null = null;

  const config = (id: LabId) => target.value === 'ssh'
    ? { target: 'ssh', host: val(`op-${id}-host`), port: Number(val(`op-${id}-sshport`)), user: val(`op-${id}-user`), mode: val(`op-${id}-mode`) }
    : { target: 'gcp', project: val('op-project'), account: val('op-account'), zone: val('op-zone'), name: val(`op-${id}-vm`), mode: val(`op-${id}-mode`) };
  const api = async (id: LabId, action: string, extra: object = {}) => {
    const r = await fetch(`/api/lab/${id}/${action}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ config: config(id), ...extra }) });
    const responseText = await r.text();
    let body: { error?: string };
    try { body = JSON.parse(responseText) as { error?: string }; }
    catch { throw new Error(responseText || `Operator API returned ${r.status}`); }
    if (!r.ok) throw new Error(body.error ?? `Operator API returned ${r.status}`);
  };
  const runBody = (seed?: number) => ({ provider: provider.value, model: model.value.trim(), agents: Number(agents.value), concurrency: Number(concurrency.value), maxToolCalls: Number(calls.value), maxModelTurns: Number(turns.value), maxTokens: Number(tokens.value), maxWallMs: Number(wallBudget.value), ...(seed ? { seed } : {}) });

  type Card = { phase: HTMLElement; output: HTMLElement; result: HTMLElement; meta: HTMLElement; plan: HTMLButtonElement; prepare: HTMLButtonElement; connect: HTMLButtonElement; run: HTMLButtonElement; teardown: HTMLButtonElement; mode: HTMLSelectElement };
  const cards = {} as Record<LabId, Card>;
  const labCard = (id: LabId) => {
    const d = LAB_DEFAULTS[id];
    const mode = h('select', { id: `op-${id}-mode`, 'aria-label': `${id} defense mode` }, ...['baseline', 'hardened', 'defended'].map((m) => h('option', { value: m }, m))) as HTMLSelectElement;
    mode.value = d.mode;
    const c: Card = {
      mode,
      phase: h('p', { class: 'chip', 'data-op-phase': id }, 'Checking local operator service…'),
      output: h('pre', { class: 'operator-output', 'aria-live': 'polite' }),
      result: h('div', { class: 'operator-result' }),
      meta: h('p', { class: 'muted small mono' }, `Tunnel 127.0.0.1:${d.port} · Live hub /hub/${id}`),
      plan: h('button', { class: 'btn', type: 'button' }, 'Review plan') as HTMLButtonElement,
      prepare: h('button', { class: 'btn btn-primary', type: 'button', disabled: 'true' }, 'Build VM') as HTMLButtonElement,
      connect: h('button', { class: 'btn', type: 'button', disabled: 'true' }, 'Start/reconnect · charges resume') as HTMLButtonElement,
      run: h('button', { class: 'btn btn-primary', type: 'button', disabled: 'true' }, 'Run test') as HTMLButtonElement,
      teardown: h('button', { class: 'btn btn-danger', type: 'button', disabled: 'true' }, 'Tear down') as HTMLButtonElement,
    };
    cards[id] = c;
    c.plan.addEventListener('click', async () => { try { await api(id, 'plan'); await poll(); } catch (e) { showError(id, e); } });
    c.prepare.addEventListener('click', async () => { try { await api(id, 'prepare'); await poll(); } catch (e) { showError(id, e); } });
    c.connect.addEventListener('click', async () => { try { await api(id, 'connect'); await poll(); } catch (e) { showError(id, e); } });
    c.run.addEventListener('click', async () => { try { await api(id, 'run', runBody()); await poll(); } catch (e) { showError(id, e); } });
    c.teardown.addEventListener('click', async () => {
      if (target.value === 'ssh') { try { await api(id, 'teardown'); await poll(); } catch (e) { showError(id, e); } return; }
      pendingTeardown = id; (root.querySelector('#op-confirm') as HTMLInputElement).value = ''; confirmation.showModal(); });
    return h('section', { class: 'operator-lab', 'data-op-lab': id },
      h('h3', {}, id.toUpperCase()),
      h('div', { class: 'operator-grid' },
        h('div', { class: 'op-gcp-only', style: 'display:contents' }, field('VM name', `op-${id}-vm`, d.name)),
        h('div', { class: 'op-ssh-only', style: 'display:contents' },
          field('SSH host', `op-${id}-host`, d.host),
          field('SSH port', `op-${id}-sshport`, d.sshPort),
          field('SSH user', `op-${id}-user`, d.user),
        ),
        h('label', { class: 'operator-field' }, h('span', {}, 'Defense mode'), mode),
      ),
      c.meta,
      h('div', { class: 'live-controls operator-actions' }, c.plan, c.prepare, c.connect, c.run, c.teardown),
      c.phase, c.result,
      h('details', {}, h('summary', {}, 'Operation record'), c.output),
    );
  };

  root.replaceChildren(
    h('section', { class: 'operator-panel' },
      h('span', { class: 'badge badge-measured' }, 'Lab operator · two-VM comparison'),
      h('p', { class: 'muted small' }, 'VM1 and VM2 are independent labs, each with its own VM, keys, defense mode and loopback tunnel. Steps: 1) Connect & start stack on both · 2) Run both · 3) watch the Live tab · 4) compare below · 5) Stop stack. Tests use synthetic records only.'),
      h('div', { class: 'operator-grid' },
        h('label', { class: 'operator-field' }, h('span', {}, 'Lab target'), target),
        h('div', { class: 'op-gcp-only', style: 'display:contents' }, project, account, zone),
        targetHelp,
        h('label', { class: 'operator-field' }, h('span', {}, 'Test provider'), provider),
        h('label', { class: 'operator-field' }, h('span', {}, 'Model ID'), model, modelPresets),
        providerHelp,
        h('label', { class: 'operator-field' }, h('span', {}, 'Swarm size'), agents),
        h('label', { class: 'operator-field' }, h('span', {}, 'Concurrent sessions per VM'), concurrency),
        h('label', { class: 'operator-field' }, h('span', {}, 'Tool calls per agent (max 50)'), calls),
        h('label', { class: 'operator-field' }, h('span', {}, 'Model turns per agent (max 50)'), turns),
        h('label', { class: 'operator-field' }, h('span', {}, 'Tokens per agent'), tokens),
        h('label', { class: 'operator-field' }, h('span', {}, 'Maximum test runtime'), wallBudget),
        h('p', { class: 'muted small' }, '"Run both" sends the same seed, agent count and role mix to both VMs, so the only intended difference is the defense mode. Through SSH tunnels, 16 concurrent sessions per VM kept transport errors to about 2%; 32 excluded about 20% of agents.'),
      ),
      h('div', { class: 'live-controls operator-actions' }, buildBoth, runBoth),
      compare,
      h('div', { class: 'operator-labs' }, labCard('vm1'), labCard('vm2')),
      confirmation,
    ),
  );

  const syncProvider = () => {
    const scripted = provider.value === 'scripted';
    model.disabled = scripted;
    for (const opt of agents.options) opt.disabled = !scripted && Number(opt.value) > 16;
    if (!scripted && Number(agents.value) > 16) agents.value = '16';
    if (provider.value === 'openai-compatible' && !['gpt-oss:120b', 'Qwen3.8-27B', 'Foundation-Sec-8B'].includes(model.value)) model.value = 'gpt-oss:120b';
    if (provider.value === 'tantular-cloud' && model.value === 'qwen3.5:4b-q8_0') model.value = 'Ollama-lokal-all-model/fervent_mcclintock/qwen3.8-27b:q4';
    providerHelp.textContent = provider.value === 'openai-compatible'
      ? 'Hosted inference sends the lab prompt and synthetic service key to the INA17 endpoint. Start the dashboard with INA17_API_KEY set in Terminal; the key is never entered here or saved in browser storage. Model runs are limited to 16 agents per VM.'
      : provider.value === 'tantular-cloud'
        ? 'Hosted inference sends only synthetic lab prompts and credentials to Tantular Cloud. The endpoint and key are read server-side from the configured .env.local file. Model runs are limited to 16 agents per VM.'
        : provider.value === 'ollama'
          ? 'Local Ollama models must already be installed and support tools. No prompts leave this machine. Model runs are limited to 16 agents per VM.'
          : 'Scripted agents do not call a language model. Each agent follows its role plan with its own signed peer identity.';
  };
  provider.addEventListener('change', syncProvider);
  const syncTarget = () => {
    const ssh = target.value === 'ssh';
    for (const el of root.querySelectorAll<HTMLElement>('.op-gcp-only')) el.style.display = ssh ? 'none' : 'contents';
    for (const el of root.querySelectorAll<HTMLElement>('.op-ssh-only')) el.style.display = ssh ? 'contents' : 'none';
    targetHelp.textContent = ssh
      ? 'Uses your own VMs. First open a shared login per VM in a Mac Terminal (asks the password once): ssh -M -S ~/.ssh/cm-vm1 -o ControlPersist=12h -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -fN -p 6522 tantular@117.54.6.226 — and the same with cm-vm2 for VM2. The dashboard never sees a password and never creates or deletes a VM.'
      : 'Creates temporary e2-small VMs in the GCP project, and deletes them on teardown. Cloud charges apply while they run.';
    buildBoth.textContent = ssh ? 'Connect & start both stacks' : 'Build both VMs';
    for (const id of LAB_IDS) {
      const c = cards[id];
      c.prepare.textContent = ssh ? 'Connect & start stack' : 'Build VM';
      c.connect.textContent = ssh ? 'Restart stack (fresh keys)' : 'Start/reconnect · charges resume';
      c.teardown.textContent = ssh ? 'Stop stack' : 'Tear down';
    }
  };
  target.addEventListener('change', syncTarget);
  const showError = (id: LabId, e: unknown) => { cards[id].phase.textContent = e instanceof Error ? e.message : String(e); cards[id].phase.className = 'chip bad'; };

  buildBoth.addEventListener('click', async () => {
    await Promise.all(LAB_IDS.map(async (id) => { try { await api(id, 'prepare'); } catch (e) { showError(id, e); } }));
    await poll();
  });
  runBoth.addEventListener('click', async () => {
    const seed = (Date.now() % 2147483646) + 1;
    await Promise.all(LAB_IDS.map(async (id) => { try { await api(id, 'run', runBody(seed)); } catch (e) { showError(id, e); } }));
    await poll();
  });
  confirmation.addEventListener('close', async () => {
    const id = pendingTeardown;
    pendingTeardown = null;
    if (confirmation.returnValue !== 'confirm' || !id) return;
    try { await api(id, 'teardown', { confirm: (root.querySelector('#op-confirm') as HTMLInputElement).value }); await poll(); } catch (e) { showError(id, e); }
  });

  const renderCompare = (labs: Record<string, LabStatus>) => {
    const rows = LAB_IDS.map((id) => ({ id, lab: labs[id], s: labs[id]?.job.result?.summary }));
    if (!rows.some((r) => r.s)) { compare.replaceChildren(); return; }
    const cell = (r: typeof rows[number], f: (s: Summary) => string) => h('td', {}, r.s ? f(r.s) : '—');
    const metric = (name: string, f: (s: Summary) => string) => h('tr', {}, h('th', { scope: 'row' }, name), ...rows.map((r) => cell(r, f)));
    compare.replaceChildren(
      h('h3', {}, 'Side-by-side result'),
      h('table', { class: 'operator-compare-table' },
        h('thead', {}, h('tr', {}, h('th', {}, ''), ...rows.map((r) => h('th', { scope: 'col' }, `${r.id.toUpperCase()} · ${r.lab?.mode ?? '?'}`)))),
        h('tbody', {},
          metric('Attested mode', (s) => s.validity?.defenseMode ?? 'not attested'),
          metric('Interpretable', (s) => (s.validity?.interpretable ? 'yes' : `no (${s.validity?.reasons.join('; ') ?? ''})`)),
          metric('Agents', (s) => String(s.agents)),
          metric('Red compromised (exported)', (s) => `${s.efficacy?.redCompromised ?? 0}/${s.efficacy?.validRed ?? 0} · ${pct(s.efficacy?.redCompromised ?? 0, s.efficacy?.validRed ?? 0)}`),
          metric('Red revoked', (s) => `${s.efficacy?.redRevoked ?? 0}/${s.efficacy?.validRed ?? 0} · ${pct(s.efficacy?.redRevoked ?? 0, s.efficacy?.validRed ?? 0)}`),
          metric('Exports blocked', (s) => `${s.exportBlocked}/${s.exportAttempts}`),
          metric('Legit exports', (s) => `${s.efficacy?.legitExported ?? 0}/${s.efficacy?.validLegit ?? 0}`),
          metric('Errors excluded', (s) => String(s.efficacy?.excludedErrors ?? 0)),
          metric('Elapsed', (s) => (s.scale ? `${(s.scale.elapsedMs / 1000).toFixed(1)} s · peak ${s.scale.peakActive}` : '—')),
        ),
      ),
    );
  };

  const poll = async () => {
    try {
      const status = await (await fetch('/api/lab/status', { cache: 'no-store' })).json() as Status;
      for (const id of LAB_IDS) {
        const lab = status.labs[id];
        const c = cards[id];
        if (!lab) continue;
        c.phase.textContent = lab.job.phase;
        c.phase.className = `chip ${lab.job.error ? 'bad' : lab.job.active ? 'warn' : 'ok'}`;
        c.output.textContent = lab.job.output.join('\n');
        c.meta.textContent = `Tunnel 127.0.0.1:${lab.port} · Live hub ${lab.hubPath}${lab.mode ? ` · running DEFENSE_MODE=${lab.mode}` : ''}${lab.stackId ? ` · stack ${lab.stackId}` : ''}`;
        if (lab.job.result) {
          const s = lab.job.result.summary;
          const legit = s.byKind?.legit;
          c.result.replaceChildren(h('p', {}, `Recorded run: ${s.agents} agents · ${s.revokedAgents} revoked · ${s.exportBlocked}/${s.exportAttempts} exports blocked${legit ? ` · legitimate exports ${legit.success}/${legit.total}` : ''}`), h('p', { class: 'mono small' }, `Evidence: ${escPath(lab.job.result.evidence)}\nResult: ${escPath(lab.job.result.result)}`));
        } else if (lab.lastEvidence) c.result.replaceChildren(h('p', { class: 'mono small' }, `Latest evidence: ${escPath(lab.lastEvidence)}`));
        const ssh = target.value === 'ssh';
        c.prepare.disabled = lab.job.active || lab.prepared || (!ssh && lab.provisioned);
        c.connect.disabled = lab.job.active || !lab.provisioned || (!ssh && lab.prepared);
        c.run.disabled = lab.job.active || !lab.prepared;
        c.teardown.disabled = lab.job.active || (!ssh && !lab.provisioned);
        c.plan.disabled = lab.job.active;
        // Mode is fixed once a stack is up; reconnect applies a changed mode.
        c.mode.disabled = lab.job.active || lab.prepared;
      }
      const all = LAB_IDS.map((id) => status.labs[id]).filter((l): l is LabStatus => !!l);
      buildBoth.disabled = target.value === 'ssh' ? all.some((l) => l.job.active) || all.every((l) => l.prepared) : all.some((l) => l.job.active || l.provisioned);
      runBoth.disabled = !all.every((l) => l.prepared && !l.job.active);
      renderCompare(status.labs);
    } catch {
      for (const id of LAB_IDS) { cards[id].phase.textContent = 'Local operator API unavailable. Start the dashboard with npm run deception-lab.'; cards[id].phase.className = 'chip bad'; }
    }
  };
  syncProvider();
  syncTarget();
  void poll();
  const timer = window.setInterval(() => { void poll(); }, 1500);
  root.addEventListener('DOMNodeRemoved', () => clearInterval(timer), { once: true });
}
