/** Local-only operator API used by the dashboard's GCP Lab tab. */
import { spawn } from 'node:child_process';
import { appendFile, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import { requireLabStackId } from '../../experiments/swarm/stack-id.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const STATE_FILE = resolve(ROOT, '.gatra/swarm-dashboard.json');
const EVIDENCE_DIR = resolve(ROOT, 'docs/evidence');
const MODES = ['baseline', 'hardened', 'defended'];
/**
 * Two independent lab VMs for side-by-side comparison. Each has its own VM,
 * keys, defense mode, local IAP tunnel port and dashboard hub path. Nothing is
 * shared between them except the operator process.
 */
export const LABS = {
  vm1: { port: 18092, hubPath: '/hub/vm1', mode: 'baseline', name: 'gatra-deception-vm1' },
  vm2: { port: 18093, hubPath: '/hub/vm2', mode: 'defended', name: 'gatra-deception-vm2' },
};
const defaults = { project: 'tantular-dashboard', zone: 'asia-southeast2-a', account: '' };
const freshState = () => ({ provisioned: false, prepared: false, keys: null, tunnel: null, lastEvidence: null, config: null });
const freshJob = () => ({ active: false, action: 'idle', phase: 'Ready', output: [], error: null, result: null });
/** @type {Record<string, { id: string, port: number, state: any, job: any }>} */
const labs = Object.fromEntries(Object.entries(LABS).map(([id, l]) => [id, { id, port: l.port, state: freshState(), job: freshJob() }]));

async function persist() {
  await mkdir(dirname(STATE_FILE), { recursive: true, mode: 0o700 });
  const safe = { labs: Object.fromEntries(Object.values(labs).map(({ id, state }) => [id, { provisioned: state.provisioned, lastEvidence: state.lastEvidence, config: state.config }])) };
  await writeFile(STATE_FILE, JSON.stringify(safe, null, 2) + '\n', { mode: 0o600 });
}
async function restore() {
  let saved = {};
  try { saved = JSON.parse(await readFile(STATE_FILE, 'utf8')); } catch {}
  for (const lab of Object.values(labs)) {
    const s = saved.labs?.[lab.id];
    if (s) Object.assign(lab.state, { provisioned: !!s.provisioned, lastEvidence: s.lastEvidence ?? null, config: s.config ?? null });
    // Credentials and tunnel processes are deliberately never restored.
    lab.state.keys = null;
    lab.state.tunnel = null;
    lab.state.prepared = false;
  }
}

function run(command, args, env = {}, onLine = () => {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { cwd: ROOT, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let pending = '';
    const consume = (chunk) => {
      pending += chunk.toString();
      const lines = pending.split(/\r?\n/);
      pending = lines.pop() ?? '';
      for (const line of lines) if (line) onLine(line);
    };
    child.stdout.on('data', consume);
    child.stderr.on('data', consume);
    child.on('error', reject);
    child.on('close', (code) => {
      if (pending) onLine(pending);
      if (code === 0) resolveRun();
      else reject(new Error(`${command} exited with status ${code}`));
    });
  });
}

export function redact(line) {
  return line.replace(/LAB_(?:CONTROL|LEGIT)_KEY=[^\s]+/g, '[REDACTED]').replace(/TANTULAR_UPSTREAM_KEY=[^\s]+/g, 'TANTULAR_UPSTREAM_KEY=[REDACTED]');
}
const outputFor = (lab) => (line) => {
  lab.job.output.push(redact(line));
  if (lab.job.output.length > 400) lab.job.output.splice(0, lab.job.output.length - 400);
};

async function runLab(lab, action, config, extraEnv = {}) {
  const env = { ...(config.account ? { GATRA_GCP_ACCOUNT: config.account } : {}), GATRA_DEFENSE_MODE: config.mode, ...extraEnv };
  await run('bash', ['cloud/gcp/lab.sh', action, config.project, config.zone, config.name], env, outputFor(lab));
}

async function tantularCloudEnv() {
  const path = process.env.TANTULAR_CLOUD_ENV_FILE;
  if (!path) throw new Error('Set TANTULAR_CLOUD_ENV_FILE to the Tantular site .env.local path before starting the dashboard.');
  const file = parseEnv(await readFile(path, 'utf8'));
  const value = (name) => String(process.env[name] ?? file[name] ?? '').trim();
  const baseUrl = value('TANTULAR_UPSTREAM_URL').replace(/\/+$/, '');
  const apiKey = value('TANTULAR_UPSTREAM_KEY');
  const auth = value('TANTULAR_UPSTREAM_AUTH') === 'x-bf-vk' ? 'x-bf-vk' : 'authorization';
  let url;
  try { url = new URL(baseUrl); } catch { throw new Error('Tantular Cloud endpoint URL is missing or invalid.'); }
  if (url.protocol !== 'https:' || url.hostname.toLowerCase() !== 'openai.ina17.com' || url.username || url.password || url.search || url.hash || (url.port && url.port !== '443')) throw new Error('Tantular Cloud must use the configured HTTPS INA17 endpoint.');
  if (apiKey.length < 8) throw new Error('Tantular Cloud authentication key is missing or invalid.');
  return { TANTULAR_UPSTREAM_URL: baseUrl, TANTULAR_UPSTREAM_KEY: apiKey, TANTULAR_UPSTREAM_AUTH: auth };
}

const hubUrl = (lab) => `http://127.0.0.1:${lab.port}`;

async function waitForHub(lab) {
  for (let i = 0; i < 30; i++) {
    try { if ((await fetch(`${hubUrl(lab)}/healthz`, { signal: AbortSignal.timeout(1000) })).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`Swarm hub did not become ready on the IAP tunnel (127.0.0.1:${lab.port}).`);
}

function startTunnel(lab, c) {
  const { state, job } = lab;
  return new Promise((resolveTunnel, reject) => {
    // Never adopt whatever already listens on this lab's port: that could be the
    // other VM's tunnel or a stale local stack. Attestation would catch it, but
    // refusing here gives a clearer error. Kill our own previous tunnel first.
    const hadTunnel = !!state.tunnel;
    state.tunnel?.kill('SIGTERM');
    state.tunnel = null;
    new Promise((r) => setTimeout(r, hadTunnel ? 1500 : 0))
      .then(() => fetch(`${hubUrl(lab)}/healthz`, { signal: AbortSignal.timeout(500) }))
      .then(() => true, () => false)
      .then((busy) => {
        if (busy) { reject(new Error(`Local port ${lab.port} already answers; stop the other tunnel or local stack before connecting ${lab.id}.`)); return; }
        const args = ['compute', 'ssh', c.name, `--project=${c.project}`, `--zone=${c.zone}`, '--tunnel-through-iap', '--quiet', '--ssh-flag=-N', '--ssh-flag=-oExitOnForwardFailure=yes', `--ssh-flag=-L ${lab.port}:localhost:18092`];
        if (c.account) args.push(`--account=${c.account}`);
        const child = spawn('gcloud', args, { cwd: ROOT, stdio: ['ignore', 'ignore', 'pipe'] });
        let errors = '';
        child.stderr.on('data', (b) => { errors = (errors + b.toString()).slice(-2000); });
        child.on('error', reject);
        child.on('spawn', () => { state.tunnel = child; resolveTunnel(); });
        child.on('exit', (code) => {
          if (state.tunnel === child) {
            state.tunnel = null;
            state.prepared = false;
            if (!lab.job.active) lab.job.phase = 'IAP tunnel closed; reconnect before the next test';
          }
          if (code && lab.job.active) outputFor(lab)(`IAP tunnel exited (${code}): ${errors.slice(-300)}`);
        });
      });
  });
}

function gcloudArgs(config, rest) {
  const args = [...rest, `--project=${config.project}`];
  if (config.zone) args.push(`--zone=${config.zone}`);
  if (config.account) args.push(`--account=${config.account}`);
  return args;
}

function instanceStatus(config) {
  return new Promise((resolveStatus, reject) => {
    const args = gcloudArgs(config, ['compute', 'instances', 'describe', config.name, '--format=value(status)']);
    const child = spawn('gcloud', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', (b) => { out += b.toString(); });
    child.stderr.on('data', (b) => { err = (err + b.toString()).slice(-1000); });
    child.on('error', reject);
    child.on('close', (code) => code === 0 ? resolveStatus(out.trim()) : reject(new Error(`Could not read VM status: ${err.trim().split('\n').at(-1) || `gcloud exited ${code}`}`)));
  });
}

async function waitForSsh(lab, config) {
  const args = gcloudArgs(config, ['compute', 'ssh', config.name, '--tunnel-through-iap', '--quiet', '--ssh-flag=-oConnectTimeout=8', '--ssh-flag=-oConnectionAttempts=1', '--command=true']);
  for (let i = 0; i < 30; i++) {
    try { await run('gcloud', args, {}, () => {}); return; } catch {}
    lab.job.phase = `Waiting for VM IAP SSH (${i + 1}/30)`;
    await new Promise((r) => setTimeout(r, 10000));
  }
  throw new Error('VM did not become reachable over IAP within five minutes. Check its GCP status and OS Login/IAP permissions.');
}

/** Shared-login socket for an operator-managed SSH lab: the operator opens it with their password. */
export const controlPath = (labId) => join(homedir(), '.ssh', `cm-${labId}`);

function validate(lab, body) {
  const raw = body?.config ?? {};
  if (raw.target === 'ssh') {
    const c = { mode: LABS[lab.id].mode, port: 22, user: '', host: '', ...raw };
    if (!MODES.includes(c.mode)) throw new Error('Defense mode must be baseline, hardened, or defended.');
    if (!/^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?)$/.test(c.host)) throw new Error(`Enter ${lab.id}'s SSH host (IP address or hostname).`);
    const port = Number(c.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SSH port must be 1–65535.');
    if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(c.user)) throw new Error('Enter the SSH user name.');
    const other = Object.values(labs).find((l) => l.id !== lab.id && l.state.config?.target === 'ssh' && l.state.config.host === c.host && l.state.config.port === port);
    if (other) throw new Error(`${c.host}:${port} is already used by ${other.id}; each lab needs its own VM.`);
    return { target: 'ssh', host: c.host, port, user: c.user, name: `${c.user}@${c.host}`, project: '', zone: '', account: '', mode: c.mode };
  }
  const c = { ...defaults, name: LABS[lab.id].name, mode: LABS[lab.id].mode, ...raw };
  if (!MODES.includes(c.mode)) throw new Error('Defense mode must be baseline, hardened, or defended.');
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(c.project)) throw new Error('Enter a valid GCP project ID.');
  if (!/^[a-z]+-[a-z0-9]+[0-9]-[a-z]$/.test(c.zone)) throw new Error('Enter a valid GCP zone.');
  if (!/^[a-z][a-z0-9-]{0,38}[a-z0-9]$/.test(c.name)) throw new Error('VM name must be 2–40 lowercase letters, numbers, or hyphens.');
  if (c.account && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.account)) throw new Error('Enter a valid GCP account email.');
  const other = Object.values(labs).find((l) => l.id !== lab.id && l.state.config && l.state.config.name === c.name && l.state.config.project === c.project);
  if (other) throw new Error(`VM name ${c.name} is already used by ${other.id}; each lab needs its own VM.`);
  return { target: 'gcp', project: c.project, zone: c.zone, name: c.name, account: c.account, mode: c.mode };
}

async function readKeys(config) {
  const capture = await new Promise((resolveCapture, reject) => {
    const args = ['compute', 'ssh', config.name, `--project=${config.project}`, `--zone=${config.zone}`, '--tunnel-through-iap', '--quiet', '--command=sudo cat /tmp/gatra-swarm-keys.env'];
    if (config.account) args.push(`--account=${config.account}`);
    const child = spawn('gcloud', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; child.stdout.on('data', (b) => { out += b.toString(); });
    child.on('error', reject); child.on('close', (code) => code === 0 ? resolveCapture(out) : reject(new Error('Could not retrieve temporary lab keys over IAP.')));
  });
  return parseKeyFile(capture);
}

/**
 * Parse the VM key file. Fails closed unless it carries both keys and a GCP
 * stack id: without one the run could not tell this VM's stack from any other
 * defended stack (for example one reporting `unlabelled`).
 */
export function parseKeyFile(text, target = 'gcp') {
  const keys = {};
  for (const line of String(text).split(/\r?\n/)) {
    if (line.startsWith('LAB_CONTROL_KEY=')) keys.controlKey = line.slice(16).trim();
    if (line.startsWith('LAB_LEGIT_KEY=')) keys.legitKey = line.slice(14).trim();
    if (line.startsWith('LAB_STACK_ID=')) keys.stackId = line.slice(13).trim();
    if (line.startsWith('DEFENSE_MODE=')) keys.mode = line.slice(13).trim();
  }
  if (!keys.controlKey || !keys.legitKey) throw new Error('Temporary swarm keys were not returned by the VM.');
  requireLabStackId(keys.stackId, target, 'VM key file LAB_STACK_ID');
  return keys;
}

/**
 * Runner arguments that make a test fail closed unless this VM's stack attests
 * the expected mode. Defaults to defended; a baseline comparison VM expects baseline.
 */
export function attestationArgs(keys, mode = 'defended', target = 'gcp') {
  if (!MODES.includes(mode)) throw new Error(`unknown defense mode ${mode}`);
  return ['--expect-mode', mode, '--expect-stack', requireLabStackId(keys?.stackId, target, 'VM key file LAB_STACK_ID')];
}

/** Scripted agents scale to 1,000 per VM; model-driven runs stay at the reviewed 16. */
export function agentLimit(provider) {
  return provider === 'scripted' ? 1000 : 16;
}

// ---- Operator-managed VMs over plain SSH (shared login opened by the operator) ----
// Never provisions or deletes anything: upload the stack, start/stop it, forward one port.
const sshDest = (c) => ['-p', String(c.port), `${c.user}@${c.host}`];
const sshOpts = (lab) => ['-S', controlPath(lab.id), '-o', 'BatchMode=yes', '-o', 'ControlMaster=no'];
function capture(command, args) {
  return new Promise((resolveCapture, reject) => {
    const child = spawn(command, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', (b) => { out += b.toString(); });
    child.stderr.on('data', (b) => { err = (err + b.toString()).slice(-1000); });
    child.on('error', reject);
    child.on('close', (code) => code === 0 ? resolveCapture(out) : reject(new Error(err.trim().split('\n').at(-1) || `${command} exited ${code}`)));
  });
}
const forwardSpec = (lab) => `${lab.port}:127.0.0.1:18092`;
const cancelForward = (lab, c) => capture('ssh', [...sshOpts(lab), '-O', 'cancel', '-L', forwardSpec(lab), ...sshDest(c)]).catch(() => {});

async function sshConnect(lab, c) {
  const { state, job } = lab;
  const addOutput = outputFor(lab);
  job.phase = `Checking your shared SSH login (${controlPath(lab.id).replace(homedir(), '~')})`;
  try { await capture('ssh', ['-S', controlPath(lab.id), '-O', 'check', ...sshDest(c)]); }
  catch { throw new Error(`No shared SSH login for ${lab.id}. In a Mac Terminal run: ssh -M -S ~/.ssh/cm-${lab.id} -o ControlPersist=12h -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -fN -p ${c.port} ${c.user}@${c.host}`); }
  const host = (await capture('ssh', [...sshOpts(lab), ...sshDest(c), 'hostname'])).trim();
  addOutput(`Connected to ${host} (${c.user}@${c.host}:${c.port}) through the shared login.`);
  if (!(await capture('ssh', [...sshOpts(lab), ...sshDest(c), 'docker info >/dev/null 2>&1 && echo ok || echo no'])).includes('ok')) {
    throw new Error(`Docker is not usable by ${c.user} on ${host}. In the VM run: sudo usermod -aG docker ${c.user}, then reopen the shared login.`);
  }
  job.phase = 'Uploading the swarm stack';
  const dir = await mkdtemp(join(tmpdir(), 'gatra-swarm-'));
  try {
    const bundle = join(dir, 'bundle.tgz');
    await run('tar', ['-czf', bundle, 'lab/swarm.compose.yaml', 'lab/services', 'lab/opencanary', 'cloud/gcp/swarm-engage.sh'], { COPYFILE_DISABLE: '1' }, addOutput);
    await run('scp', ['-q', '-o', `ControlPath=${controlPath(lab.id)}`, '-o', 'BatchMode=yes', '-P', String(c.port), bundle, `${c.user}@${c.host}:/tmp/gatra-swarm-bundle.tgz`], {}, addOutput);
  } finally { await rm(dir, { recursive: true, force: true }); }
  job.phase = `Starting the swarm stack with fresh keys (DEFENSE_MODE=${c.mode})`;
  await cancelForward(lab, c);
  state.tunnel = null;
  const quiet = (line) => { if (!/LIBARCHIVE|Pulling|Waiting|Download|Extracting|Verifying|Pull complete/.test(line)) addOutput(line); };
  await run('ssh', [...sshOpts(lab), ...sshDest(c), `mkdir -p ~/deception-lab && tar -xzf /tmp/gatra-swarm-bundle.tgz -C ~/deception-lab 2>/dev/null; cd ~/deception-lab && (bash cloud/gcp/swarm-engage.sh stop >/dev/null 2>&1 || true) && GATRA_STACK_PREFIX=ssh bash cloud/gcp/swarm-engage.sh start ${c.mode}`], {}, quiet);
  state.keys = parseKeyFile(await capture('ssh', [...sshOpts(lab), ...sshDest(c), 'cat /tmp/gatra-swarm-keys.env']), 'ssh');
  if (state.keys.mode !== c.mode) throw new Error(`VM reports DEFENSE_MODE=${state.keys.mode ?? 'unset'}, expected ${c.mode}.`);
  job.phase = `Opening the SSH tunnel on 127.0.0.1:${lab.port}`;
  if (await fetch(`${hubUrl(lab)}/healthz`, { signal: AbortSignal.timeout(500) }).then(() => true, () => false)) {
    throw new Error(`Local port ${lab.port} is already in use by something else; stop it and connect ${lab.id} again.`);
  }
  await capture('ssh', [...sshOpts(lab), '-O', 'forward', '-L', forwardSpec(lab), ...sshDest(c)]);
  state.tunnel = { kill: () => { void cancelForward(lab, c); } };
  await waitForHub(lab);
  state.provisioned = true;
  state.prepared = true;
  state.config = c;
  await persist();
  job.phase = `Ready: ${host} stack ${state.keys.stackId} (${c.mode}) on 127.0.0.1:${lab.port}`;
}

async function sshStop(lab, c) {
  const { job } = lab;
  job.phase = 'Stopping the swarm stack on the VM';
  await run('ssh', [...sshOpts(lab), ...sshDest(c), 'cd ~/deception-lab && bash cloud/gcp/swarm-engage.sh stop'], {}, outputFor(lab));
  await cancelForward(lab, c);
  lab.state = { ...freshState(), lastEvidence: lab.state.lastEvidence };
  await persist();
  job.phase = 'Stack stopped; tunnel closed. The VM itself is untouched.';
}

async function startSwarm(lab, config) {
  const { state, job } = lab;
  job.phase = `Starting the swarm services (DEFENSE_MODE=${config.mode})`;
  await runLab(lab, 'swarm', config);
  state.keys = await readKeys(config);
  if (state.keys.mode !== config.mode) throw new Error(`VM reports DEFENSE_MODE=${state.keys.mode ?? 'unset'}, expected ${config.mode}.`);
  await startTunnel(lab, config);
  await waitForHub(lab);
  state.prepared = true;
  await persist();
}

async function prepare(lab, config) {
  const { state, job } = lab;
  job.phase = 'Provisioning the named VM and isolated lab network';
  // Give a two-hour test setup and teardown margin before the VM auto-stops.
  await runLab(lab, 'deploy', config, { GATRA_SKIP_REMOTE_DEMO: '1', GATRA_VM_MAX_RUN: '10800s' });
  state.provisioned = true;
  state.config = config;
  await persist();
  await startSwarm(lab, config);
  job.phase = `Ready: IAP tunnel on 127.0.0.1:${lab.port} and swarm hub are live`;
}

async function writeEvidence(lab, config, resultPath, provider, model) {
  const { state, job } = lab;
  const report = JSON.parse(await readFile(resultPath, 'utf8'));
  const id = report.engagementId.replace(/[^a-zA-Z0-9-]/g, '-');
  const path = resolve(EVIDENCE_DIR, `${report.startedAt.slice(0, 10)}-dashboard-${id}.md`);
  const s = report.summary;
  const lines = [
    `# Dashboard-recorded ${config.target === 'ssh' ? 'SSH VM' : 'GCP'} swarm engagement (${lab.id})`, '',
    `- Engagement: \`${report.engagementId}\``, `- Run window: ${report.startedAt} – ${report.completedAt}`,
    config.target === 'ssh'
      ? `- VM (operator-managed, SSH): \`${config.user}@${config.host}:${config.port}\` (${lab.id}, expected DEFENSE_MODE=${config.mode}); not a GCP VM`
      : `- GCP: project \`${config.project}\`, zone \`${config.zone}\`, VM \`${config.name}\` (${lab.id}, expected DEFENSE_MODE=${config.mode})`,
    `- Seed: ${report.seed}; concurrency ${s.scale?.concurrency ?? '?'}; peak active ${s.scale?.peakActive ?? '?'}; elapsed ${((s.scale?.elapsedMs ?? 0) / 1000).toFixed(1)} s; telemetry dropped ${s.scale?.telemetryDropped ?? '?'}`,
    `- Provider: ${provider}${model ? ` (${model})` : ''}`, `- Agents: ${s.agents}; revoked ${s.revokedAgents}; blocked exports ${s.exportBlocked}/${s.exportAttempts}; egress blocks ${s.egressBlocked}`,
    `- Legit client exports: ${s.byKind?.legit?.success ?? 0}/${s.byKind?.legit?.total ?? 0}`,
    `- Egress probes (outbound callout, default-deny): ${s.egress?.denied ?? 0} denied / ${s.egress?.attempts ?? 0} attempted${s.egress?.allowed ? `; ${s.egress.allowed} ALLOWED — egress policy failed` : ''}`,
    `- Stack attestation: ${report.attestation?.status === 'verified' ? `verified, stack \`${report.attestation.stackId}\`, DEFENSE_MODE=${report.attestation.mode}` : `NOT verified (${report.attestation?.reason ?? 'not recorded'})`}`,
    `- Validity: ${s.validity?.defendedRun ? 'interpretable defended run' : `not a defended-run result${s.validity?.reasons?.length ? ` (${s.validity.reasons.join('; ')})` : ''}`}`,
    ...(report.agents.length <= 32
      ? report.agents.map((a) => `- ${a.agentId} (${a.role}, ${a.kind}): ${a.outcome}; stopped by ${a.result?.stopReason ?? 'completion'}`)
      : roleTally(report.agents)),
    `- Result: \`${resultPath.replace(`${ROOT}/`, '')}\``, `- Journal: \`${resultPath.replace(/\.json$/, '.json.jsonl').replace(`${ROOT}/`, '')}\``,
    `- Digest: \`${report.digest}\` (SHA-256 integrity digest; not a signature)`,
    '- Scope: bounded synthetic lab engagement; no production data or services.',
    '- VM lifecycle: provisioned through the dashboard; teardown status is recorded by the dashboard after cleanup.', '',
  ];
  await mkdir(EVIDENCE_DIR, { recursive: true });
  await writeFile(path, lines.join('\n'), { flag: 'wx' });
  state.lastEvidence = path;
  await persist();
  job.result = { result: resultPath, evidence: path, summary: s };
}

function roleTally(agents) {
  const byRole = new Map();
  for (const a of agents) {
    const t = byRole.get(a.role) ?? {};
    t[a.outcome] = (t[a.outcome] ?? 0) + 1;
    byRole.set(a.role, t);
  }
  return [...byRole].map(([role, t]) => `- Role ${role}: ${Object.entries(t).map(([o, n]) => `${o} ${n}`).join(', ')}`);
}

/** plan / connect (prepare) / stop (teardown) for an operator-managed SSH VM. */
function sshAction(lab, name, config) {
  if (name === 'plan') {
    lab.job = { active: false, action: name, phase: 'Plan ready; nothing contacted yet', output: [
      `${lab.id}: your VM ${config.user}@${config.host}:${config.port}; DEFENSE_MODE=${config.mode}; local tunnel 127.0.0.1:${lab.port}.`,
      `Uses your shared SSH login at ~/.ssh/cm-${lab.id}; the dashboard never sees a password.`,
      'Uploads the swarm stack to ~/deception-lab, restarts it with fresh per-run keys, and forwards one local port to the VM loopback hub.',
      'Requires Docker usable by that user (docker group). Publishes only 127.0.0.1:18092 on the VM; no public ports.',
      'Nothing is created or deleted on the VM besides ~/deception-lab, the lab containers and /tmp/gatra-swarm-keys.env.',
    ], error: null, result: null };
    return;
  }
  const job = lab.job = { active: true, action: name, phase: 'Starting', output: [], error: null, result: null };
  (async () => {
    try {
      if (name === 'prepare' || name === 'connect') await sshConnect(lab, config);
      if (name === 'teardown') await sshStop(lab, config);
      job.active = false;
    } catch (e) {
      job.active = false; job.error = e instanceof Error ? e.message : String(e); job.phase = 'Action failed; inspect the output before retrying'; outputFor(lab)(`ERROR: ${job.error}`);
    }
  })();
}

async function action(labId, name, body) {
  const lab = labs[labId];
  if (!lab) throw new Error('Unknown lab; choose vm1 or vm2.');
  let { state, job } = lab;
  if (job.active) throw new Error(`Another ${lab.id} operation is already running.`);
  const config = validate(lab, body);
  if (!['plan', 'prepare', 'connect', 'run', 'teardown'].includes(name)) throw new Error('Unknown operator action.');
  if (state.provisioned && state.config && (state.config.target ?? 'gcp') !== config.target) throw new Error(`${lab.id} is tracking a ${state.config.target ?? 'gcp'} lab; stop or tear it down before switching target.`);
  if (config.target === 'ssh' && name !== 'run') return sshAction(lab, name, config);
  if (name === 'plan') {
    lab.job = { active: false, action: name, phase: 'Plan ready; no cloud calls made', output: [
      `${lab.id}: project ${config.project}; zone ${config.zone}; VM ${config.name}; DEFENSE_MODE=${config.mode}; local tunnel 127.0.0.1:${lab.port}.`,
      `Account: ${config.account || 'gcloud-selected account (enter an email to pin it explicitly)'}.`,
      'Will create an e2-small Ubuntu VM, 20 GB auto-delete boot disk, dedicated subnet and IAP-only SSH rule.',
      'Will start the swarm services, keep the IAP tunnel on localhost, and use synthetic records only.',
      'The hub has an in-process upstream allowlist. A GCP host firewall rule blocking container egress has not been validated.',
      'VM auto-stops after three hours, leaving setup/teardown margin for a two-hour test; deleting the lab also removes its named firewall/network resources.',
    ], error: null, result: null };
    return;
  }
  if (name === 'prepare' && state.provisioned) throw new Error('A VM is already marked prepared. Tear it down first or inspect the GCP project.');
  if (name === 'connect' && !state.provisioned) throw new Error('Build the VM first.');
  if (['run', 'teardown'].includes(name) && state.config && (state.config.project !== config.project || state.config.zone !== config.zone || state.config.name !== config.name)) throw new Error(`Project, zone, and VM name must match the ${lab.id} lab tracked by this dashboard.`);
  if (name === 'run' && state.config && state.config.mode !== config.mode) throw new Error(`${lab.id} was started with DEFENSE_MODE=${state.config.mode}; reconnect to change mode.`);
  if (name === 'run' && (!state.prepared || !state.keys || !state.tunnel)) throw new Error('Prepare the VM and IAP tunnel before starting a test.');
  if (name === 'teardown' && body?.confirm !== config.name) throw new Error(`Type the VM name exactly (${config.name}) to confirm teardown.`);

  job = lab.job = { active: true, action: name, phase: 'Starting', output: [], error: null, result: null };
  const addOutput = outputFor(lab);
  (async () => {
    try {
      if (name === 'prepare') await prepare(lab, config);
      if (name === 'connect') {
        if (state.config && (state.config.project !== config.project || state.config.zone !== config.zone || state.config.name !== config.name)) throw new Error('Reconnect settings must match the VM previously provisioned by this dashboard.');
        state.config = config;
        job.phase = 'Checking GCP VM state';
        const status = await instanceStatus(config);
        if (status === 'TERMINATED') {
          job.phase = 'Starting stopped VM; GCP compute charges will resume';
          await run('gcloud', gcloudArgs(config, ['compute', 'instances', 'start', config.name, '--quiet']), {}, addOutput);
        } else if (status !== 'RUNNING') {
          throw new Error(`VM is ${status}; wait for its GCP state to settle, then reconnect.`);
        }
        await waitForSsh(lab, config);
        job.phase = 'Restarting swarm services with fresh per-run keys';
        await runLab(lab, 'swarm-stop', config);
        await startSwarm(lab, config);
        job.phase = `Reconnected: swarm hub and IAP tunnel on 127.0.0.1:${lab.port} are ready`;
      }
      if (name === 'run') {
        const provider = ['ollama', 'openai-compatible', 'tantular-cloud'].includes(body.provider) ? body.provider : 'scripted';
        const model = provider === 'ollama' ? String(body.model ?? '').trim() : '';
        const selectedModel = ['openai-compatible', 'tantular-cloud'].includes(provider) ? String(body.model ?? '').trim() : model;
        if (provider === 'ollama' && !/^[\w./:-]{1,100}$/.test(model)) throw new Error('Enter the local Ollama model name.');
        if (['openai-compatible', 'tantular-cloud'].includes(provider) && !/^[\w./:-]{1,180}$/.test(selectedModel)) throw new Error('Enter the exact model ID advertised by the hosted endpoint.');
        if (provider === 'openai-compatible' && !(process.env.INA17_API_KEY ?? process.env.OPENAI_API_KEY)) throw new Error('The dashboard was started without INA17_API_KEY or OPENAI_API_KEY. Stop it, set the key in Terminal, then restart the dashboard.');
        const providerEnv = provider === 'tantular-cloud' ? await tantularCloudEnv() : {};
        const agents = Math.max(1, Math.min(agentLimit(provider), Number(body.agents) || 16));
        // Bound simultaneous sessions through the IAP tunnel; the local 250-wide burst reset connections.
        const concurrency = Math.max(1, Math.min(agents, 64, Number(body.concurrency) || 16));
        const seed = Number.isInteger(body.seed) && body.seed > 0 && body.seed < 2147483647 ? body.seed : Date.now() % 2147483646 + 1;
        const maxToolCalls = Math.max(8, Math.min(50, Number(body.maxToolCalls) || 30));
        const maxModelTurns = Number(body.maxModelTurns) || 50;
        const maxTokens = Number(body.maxTokens) || 120000;
        if (![14, 30, 50].includes(maxModelTurns)) throw new Error('Choose 14, 30, or 50 model turns per agent.');
        if (![60000, 120000, 240000].includes(maxTokens)) throw new Error('Choose 60,000, 120,000, or 240,000 tokens per agent.');
        const requestedWallMs = Number(body.maxWallMs) || 7200000;
        const allowedWallMs = new Set([600000, 1800000, 7200000]);
        if (!allowedWallMs.has(requestedWallMs)) throw new Error('Choose a 10-minute, 30-minute, or 2-hour test runtime.');
        const before = new Set(await readdir(resolve(ROOT, 'experiments/swarm/results')));
        job.phase = `Running ${agents} agents (seed ${seed}); watching the Live feed`;
        const args = ['experiments/swarm/run.mjs', '--provider', provider, '--agents', String(agents), '--concurrency', String(concurrency), '--label', lab.id, '--target', hubUrl(lab), '--hub', hubUrl(lab), '--seed', String(seed), '--max-wall-ms', String(requestedWallMs), '--max-tool-calls', String(maxToolCalls), '--max-model-turns', String(maxModelTurns), '--max-tokens', String(maxTokens)];
        if (selectedModel) args.push('--model', selectedModel);
        // Fail closed unless the stack behind this lab's tunnel attests, under the
        // control key read from this VM, that it is this VM's stack in the expected
        // mode. The other VM or a stale local stack cannot produce that attestation.
        args.push(...attestationArgs(state.keys, config.mode, config.target));
        await run('node', args, { ...providerEnv, LAB_CONTROL_KEY: state.keys.controlKey, LAB_LEGIT_KEY: state.keys.legitKey }, addOutput);
        const files = (await readdir(resolve(ROOT, 'experiments/swarm/results'))).filter((f) => f.startsWith(`result-swarm-${lab.id}-`) && f.endsWith('.json') && !before.has(f)).sort();
        if (!files.length) throw new Error('Runner finished without a new result artifact.');
        await writeEvidence(lab, config, resolve(ROOT, 'experiments/swarm/results', files.at(-1)), provider, selectedModel);
        job.phase = 'Test recorded; review the result and evidence note before teardown';
      }
      if (name === 'teardown') {
        job.phase = 'Stopping swarm services';
        if (state.prepared) await runLab(lab, 'swarm-stop', config);
        state.tunnel?.kill('SIGTERM'); state.tunnel = null;
        job.phase = 'Deleting the named VM, disk, firewall rule, subnet and network';
        await runLab(lab, 'cleanup', config);
        state = lab.state = { ...freshState(), lastEvidence: state.lastEvidence };
        await persist();
        if (state.lastEvidence) await appendFile(state.lastEvidence, `\n- Teardown: completed for VM \`${config.name}\` in project \`${config.project}\`; evidence artifacts retained locally.\n`);
        job.phase = 'Teardown complete; evidence retained locally';
      }
      job.active = false;
    } catch (e) {
      job.active = false; job.error = e instanceof Error ? e.message : String(e); job.phase = 'Action failed; inspect output and cloud state before retrying'; addOutput(`ERROR: ${job.error}`);
    }
  })();
}

/** Refresh one lab's tunnel/hub health and return its public (secret-free) status. */
async function labStatus(lab) {
  const { state, job } = lab;
  if (state.prepared && (!state.keys || !state.tunnel)) {
    state.prepared = false;
    if (!job.active) job.phase = 'IAP tunnel lost; reconnect before testing';
  }
  if (state.prepared && state.tunnel) {
    try {
      if (!(await fetch(`${hubUrl(lab)}/healthz`, { signal: AbortSignal.timeout(1200) })).ok) throw new Error('hub unavailable');
    } catch {
      state.prepared = false;
      state.tunnel?.kill('SIGTERM');
      state.tunnel = null;
      if (!job.active) job.phase = 'IAP tunnel or hub is unavailable; reconnect before testing';
    }
  }
  return { id: lab.id, port: lab.port, hubPath: LABS[lab.id].hubPath, defaults: { name: LABS[lab.id].name, mode: LABS[lab.id].mode }, mode: state.config?.mode ?? null, name: state.config?.name ?? null, target: state.config?.target ?? null, stackId: state.keys?.stackId ?? null, job, provisioned: state.provisioned, prepared: state.prepared, lastEvidence: state.lastEvidence };
}


/* ---------- recorded results for the topology replay (read-only) ---------- */

const RESULTS_DIR = resolve(ROOT, 'experiments/swarm/results');
/** Exact runner result names only: no path separators, no journals, lowercase labels. */
export const resultFileOk = (name) => typeof name === 'string' && /^result-swarm-(?:[a-z0-9][a-z0-9-]{0,23}-)?\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d-\d{3}Z\.json$/.test(name);

/** The parts of a result the replay needs: per-agent requests instead of full logs, no answers. */
export function compactResult(r) {
  return {
    format: r.format, engagementId: r.engagementId, startedAt: r.startedAt, completedAt: r.completedAt, provider: r.provider,
    label: r.label ?? null, seed: r.seed ?? null, attestation: r.attestation ?? null, expected: r.expected ?? null,
    summary: { efficacy: r.summary?.efficacy ?? null, egress: r.summary?.egress ?? null, validity: { interpretable: r.summary?.validity?.interpretable ?? null, reasons: r.summary?.validity?.reasons ?? [] } },
    agents: (r.agents ?? []).map((a) => ({
      agentId: a.agentId, role: a.role, kind: a.kind, outcome: a.outcome, durationMs: a.durationMs,
      stopReason: a.result?.stopReason ?? a.error ?? null,
      calls: (a.log ?? []).filter((x) => x.type === 'tool.http').map((x) => ({ method: x.method, path: String(x.path ?? '').replace(/^\/lab(?=\/)/, ''), status: x.status, authorized: x.authorized === true })),
    })),
  };
}

const resultIndexCache = new Map();
async function listResults() {
  const names = (await readdir(RESULTS_DIR).catch(() => [])).filter(resultFileOk).sort().reverse().slice(0, 60);
  const out = [];
  for (const file of names) {
    try {
      const { mtimeMs } = await stat(join(RESULTS_DIR, file));
      let row = resultIndexCache.get(file);
      if (!row || row.mtimeMs !== mtimeMs) {
        const r = JSON.parse(await readFile(join(RESULTS_DIR, file), 'utf8'));
        if (r.format !== 'gatra/swarm-engagement@1') continue;
        row = {
          mtimeMs, file, label: r.label ?? null, startedAt: r.startedAt, provider: r.provider,
          mode: r.attestation?.mode ?? r.expected?.mode ?? null, attested: r.attestation?.status === 'verified',
          stackId: r.attestation?.stackId ?? r.expected?.stack ?? null, agents: r.agents?.length ?? 0,
          interpretable: r.summary?.validity?.interpretable ?? null,
        };
        resultIndexCache.set(file, row);
      }
      const { mtimeMs: _m, ...pub } = row;
      out.push(pub);
    } catch { /* skip unreadable files */ }
  }
  return out;
}

export function dashboardControl() {
  return {
    name: 'deception-lab-dashboard-control',
    configureServer(server) {
      void restore();
      server.httpServer?.once('close', () => { for (const lab of Object.values(labs)) { lab.state.tunnel?.kill('SIGTERM'); lab.state.tunnel = null; } });
      server.middlewares.use('/api/lab', (req, res, next) => {
        if (req.method === 'GET' && req.url === '/status') {
          void Promise.all(Object.values(labs).map(labStatus)).then((list) => {
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ labs: Object.fromEntries(list.map((l) => [l.id, l])) }));
          });
          return;
        }
        if (req.method === 'GET' && req.url === '/results') {
          void listResults().then((rows) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ results: rows })); });
          return;
        }
        const rm = /^\/results\/([^/?#]+)$/.exec(req.url ?? '');
        if (req.method === 'GET' && rm) {
          const file = rm[1];
          if (!resultFileOk(file)) { res.writeHead(400).end('bad result name'); return; }
          void readFile(join(RESULTS_DIR, file), 'utf8').then((text) => {
            res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
            res.end(JSON.stringify(compactResult(JSON.parse(text))));
          }).catch(() => { res.writeHead(404).end('not found'); });
          return;
        }
        const m = /^\/(vm1|vm2)\/(plan|prepare|connect|run|teardown)$/.exec(req.url ?? '');
        if (req.method !== 'POST' || !m) return next();
        const [, labId, name] = m;
        if (req.headers.origin) {
          let origin;
          try { origin = new URL(req.headers.origin); } catch { res.writeHead(403).end('loopback dashboard origin required'); return; }
          const port = String(server.config.server.port ?? 3100);
          if (origin.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname) || origin.port !== port || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) {
            res.writeHead(403).end('loopback dashboard origin required'); return;
          }
        }
        let raw = ''; req.on('data', (chunk) => { raw += chunk; if (raw.length > 8192) req.destroy(); });
        req.on('end', () => {
          try {
            const body = raw ? JSON.parse(raw) : {};
            void action(labId, name, body).then(() => { res.writeHead(202, { 'content-type': 'application/json' }); res.end(JSON.stringify({ accepted: true })); }).catch((e) => {
              const lab = labs[labId];
              if (lab && !lab.job.active) {
                lab.job.action = name;
                lab.job.error = e instanceof Error ? e.message : String(e);
                lab.job.phase = lab.job.error;
                outputFor(lab)(`ERROR: ${lab.job.error}`);
              }
              res.writeHead(400, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: e.message }));
            });
          } catch (e) { res.writeHead(400, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: e.message })); }
        });
      });
    },
  };
}
