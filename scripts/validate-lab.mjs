// Runtime security validation of the optional container lab.
//   npm run deception-lab:validate-lab
// Requires a running Docker daemon. Brings the lab up under a dedicated
// project name, runs configuration, isolation, resource-limit and containment
// checks, writes evidence to docs/evidence/, and tears everything down.
// If Docker is unavailable it says so and exits 3 without claiming anything.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { LAB_ROOT } from './browser.mjs';

const COMPOSE = join(LAB_ROOT, 'lab', 'compose.yaml');
const PROJECT = 'gatra-deception-lab-validate';
const WITH_CANARY = process.argv.includes('--opencanary');
const EVIDENCE_DIR = join(LAB_ROOT, 'docs', 'evidence');

const sh = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout ?? 120000, env: { ...process.env, ...(opts.env ?? {}) } });
  return { code: r.status ?? -1, out: `${r.stdout ?? ''}${r.stderr ?? ''}`.trim() };
};
const dc = (...args) => sh('docker', ['compose', '-p', PROJECT, '-f', COMPOSE, ...(WITH_CANARY ? ['--profile', 'opencanary'] : []), ...args], { env: { LAB_MODE: 'static' }, timeout: 180000 });
const exec = (svc, script, timeout) => dc('exec', '-T', svc, 'sh', '-c', script, ...(timeout ? [] : []));

const checks = [];
const check = (id, area, description, pass, observed) => {
  checks.push({ id, area, description, pass: Boolean(pass), observed: String(observed).slice(0, 600) });
  console.log(`${pass ? '  PASS' : '  FAIL'}  ${id}  ${description}`);
};

const info = sh('docker', ['info', '--format', '{{.ServerVersion}} | {{.OperatingSystem}} | {{.Architecture}} | cgroup v{{.CgroupVersion}}']);
if (info.code !== 0) {
  console.error('Docker daemon is not reachable. Runtime validation NOT performed.\n' + info.out.split('\n')[0]);
  process.exit(3);
}
console.log(`Docker: ${info.out}`);

dc('down', '-v', '--remove-orphans');
const up = dc('up', '-d', 'collector', 'honeypot', ...(WITH_CANARY ? ['canary-adapter', 'opencanary'] : []));
if (up.code !== 0) {
  console.error(up.out);
  process.exit(1);
}
for (let i = 0; i < 30; i++) {
  if (dc('logs', 'honeypot').out.includes('"listening":8080')) break;
  await new Promise((r) => setTimeout(r, 500));
}

try {
  const cid = (svc) => dc('ps', '-q', svc).out.split('\n')[0];
  const inspect = (svc) => JSON.parse(sh('docker', ['inspect', cid(svc)]).out)[0];

  // ---------- configuration (docker inspect) ----------
  for (const svc of ['collector', 'honeypot']) {
    const c = inspect(svc);
    const hc = c.HostConfig;
    check(`CFG-${svc}-user`, 'config', `${svc}: runs as non-root 10001:10001`, c.Config.User === '10001:10001', c.Config.User);
    check(`CFG-${svc}-rofs`, 'config', `${svc}: read-only root filesystem`, hc.ReadonlyRootfs === true, hc.ReadonlyRootfs);
    check(`CFG-${svc}-caps`, 'config', `${svc}: all capabilities dropped, none added`, (hc.CapDrop ?? []).includes('ALL') && !(hc.CapAdd ?? []).length, `CapDrop=${JSON.stringify(hc.CapDrop)} CapAdd=${JSON.stringify(hc.CapAdd)}`);
    check(`CFG-${svc}-nnp`, 'config', `${svc}: no-new-privileges`, (hc.SecurityOpt ?? []).includes('no-new-privileges:true'), JSON.stringify(hc.SecurityOpt));
    check(`CFG-${svc}-priv`, 'config', `${svc}: not privileged`, hc.Privileged === false, hc.Privileged);
    check(`CFG-${svc}-mem`, 'config', `${svc}: memory limit 128 MiB`, hc.Memory === 134217728, hc.Memory);
    check(`CFG-${svc}-cpu`, 'config', `${svc}: CPU limit 0.25`, hc.NanoCpus === 250000000, hc.NanoCpus);
    check(`CFG-${svc}-pids`, 'config', `${svc}: PID limit 64`, hc.PidsLimit === 64, hc.PidsLimit);
    const mounts = c.Mounts.map((m) => `${m.Type}:${m.Destination}:${m.RW ? 'rw' : 'ro'}`);
    check(`CFG-${svc}-mounts`, 'config', `${svc}: only /app (read-only) mounted; no Docker socket`, c.Mounts.length === 1 && c.Mounts[0].Destination === '/app' && c.Mounts[0].RW === false, mounts.join(', '));
    const published = Object.values(c.NetworkSettings.Ports ?? {}).filter(Boolean).flat();
    check(`CFG-${svc}-ports`, 'config', `${svc}: no ports published to the host`, published.length === 0, JSON.stringify(c.NetworkSettings.Ports));
    const secretEnv = (c.Config.Env ?? []).filter((e) => /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(e.split('=')[0]));
    check(`CFG-${svc}-env`, 'config', `${svc}: no credential-like environment variables`, secretEnv.length === 0, secretEnv.join(', ') || 'none');
    const nets = Object.keys(c.NetworkSettings.Networks);
    check(`CFG-${svc}-nets`, 'config', `${svc}: attached only to the lab network`, nets.length === 1 && nets[0].endsWith('lab_internal'), nets.join(', '));
  }
  const netName = Object.keys(inspect('honeypot').NetworkSettings.Networks)[0];
  const net = JSON.parse(sh('docker', ['network', 'inspect', netName]).out)[0];
  check('NET-internal', 'isolation', 'lab network is internal (no route off the host)', net.Internal === true, `Internal=${net.Internal}`);

  // ---------- runtime isolation (docker exec) ----------
  const id = exec('honeypot', 'id -u; id -g');
  check('RT-uid', 'runtime', 'process uid/gid inside container is 10001', id.out.replace(/\s+/g, ' ') === '10001 10001', id.out);
  const rootWrite = exec('honeypot', 'touch /probe 2>&1; echo rc=$?');
  check('RT-rootfs-write', 'runtime', 'writing to / fails (read-only)', /rc=[1-9]/.test(rootWrite.out), rootWrite.out);
  const appWrite = exec('honeypot', 'touch /app/probe 2>&1; echo rc=$?');
  check('RT-app-write', 'runtime', 'writing to /app fails (read-only bind)', /rc=[1-9]/.test(appWrite.out), appWrite.out);
  const tmpExec = exec('honeypot', "printf '#!/bin/sh\\necho ran' > /tmp/x.sh && chmod +x /tmp/x.sh && /tmp/x.sh 2>&1; echo rc=$?");
  check('RT-tmp-noexec', 'runtime', '/tmp is writable but noexec', /rc=[1-9]/.test(tmpExec.out) && !/^ran$/m.test(tmpExec.out), tmpExec.out);
  const status = exec('honeypot', "grep -E '^(CapEff|CapPrm|NoNewPrivs)' /proc/self/status");
  check('RT-caps', 'runtime', 'effective capabilities empty and NoNewPrivs=1', /CapEff:\s+0{16}/.test(status.out) && /NoNewPrivs:\s+1/.test(status.out), status.out);
  const sock = exec('honeypot', 'ls -la /var/run/docker.sock /run/docker.sock 2>&1; echo done');
  check('RT-no-socket', 'runtime', 'Docker socket not present', !/srw/.test(sock.out), sock.out);

  const egressJs = `const t=(u)=>fetch(u,{signal:AbortSignal.timeout(3000)}).then(()=>'REACHED').catch(e=>'blocked:'+(e.cause?.code??e.name));
const dns=require('node:dns').promises;
(async()=>{console.log(JSON.stringify({ip:await t('http://203.0.113.45/'),https:await t('https://example.com/'),cf:await t('http://1.1.1.1/'),dns:await dns.lookup('example.com').then(()=>'RESOLVED').catch(e=>'failed:'+e.code)}))})()`;
  const eg = exec('honeypot', `node -e "${egressJs.replace(/"/g, '\\"')}"`);
  let egress = {};
  try {
    egress = JSON.parse(eg.out.split('\n').pop());
  } catch {}
  check('ISO-egress-ip', 'isolation', 'outbound HTTP to 203.0.113.45 fails', String(egress.ip).startsWith('blocked'), egress.ip ?? eg.out);
  check('ISO-egress-https', 'isolation', 'outbound HTTPS to example.com fails', String(egress.https).startsWith('blocked'), egress.https ?? eg.out);
  check('ISO-egress-cf', 'isolation', 'outbound HTTP to 1.1.1.1 fails', String(egress.cf).startsWith('blocked'), egress.cf ?? eg.out);
  check('ISO-dns', 'isolation', 'external DNS resolution fails', String(egress.dns).startsWith('failed'), egress.dns ?? eg.out);
  const internal = exec(
    'honeypot',
    `node -e "fetch('http://collector:4318/v1/events',{method:'POST',body:'{}',headers:{'content-type':'application/json'}}).then(r=>console.log('status',r.status)).catch(e=>console.log('fail',e.cause?.code))"`,
  );
  check('ISO-allowlisted', 'isolation', 'allow-listed collector is reachable from the honeypot', /status 202/.test(internal.out), internal.out);
  const hostPort = sh('docker', ['port', cid('honeypot')]);
  check('ISO-host-exposure', 'isolation', 'honeypot not exposed on any host port', hostPort.out === '', hostPort.out || '(none)');

  // ---------- containment boundary (agent run) ----------
  const drv = dc('run', '--rm', 'driver');
  let verdict = {};
  try {
    verdict = JSON.parse(drv.out.split('\n').filter((l) => l.includes('"driver":"verdict"')).pop());
  } catch {}
  check('BND-agent-ran', 'containment', 'scripted agent ran inside the lab against the honeypot only', verdict.agent?.toolCalls > 0, JSON.stringify(verdict.agent ?? drv.out.slice(-300)));

  check('BND-guard', 'containment', 'guard refuses an absolute external URL', verdict.guard?.absoluteUrl === 'refused', verdict.guard?.absoluteUrl);
  for (const [url, res] of Object.entries(verdict.egress ?? {})) check(`BND-egress-${url}`, 'containment', `driver container cannot reach ${url}`, String(res).startsWith('blocked'), res);
  const hpLogs = dc('logs', 'honeypot').out;
  const canary = /"type":"canary.used"/.test(hpLogs);
  const terminated = /"action":"terminate_session"/.test(hpLogs);
  check('BND-canary', 'containment', 'honeypot recorded canary use and terminated the session', canary && terminated, hpLogs.split('\n').filter((l) => /canary|terminate/.test(l)).slice(0, 2).join(' | ') || '(no canary/terminate events)');
  // Positive evidence required: a broken target would also yield "no answer".
  check(
    'BND-agent-contained',
    'containment',
    'agent was contained before the real objective (>=5 calls, canary fired, no answer)',
    verdict.agent?.toolCalls >= 5 && canary && terminated && !verdict.agent?.answer,
    `toolCalls=${verdict.agent?.toolCalls} answer=${verdict.agent?.answer} canary=${canary} terminated=${terminated}`,
  );
  const colLogs = dc('logs', 'collector').out;
  const received = (colLogs.match(/collector_seq/g) ?? []).length;
  check('BND-telemetry', 'containment', 'collector received honeypot telemetry over the internal network', received > 0, `${received} events`);

  // ---------- optional OpenCanary integration (feature flag) ----------
  if (WITH_CANARY) {
    for (let i = 0; i < 30 && !/starting on 8081/.test(dc('logs', 'opencanary').out); i++) await new Promise((r) => setTimeout(r, 500));
    const oc = inspect('opencanary');
    const och = oc.HostConfig;
    check('OC-user', 'opencanary', 'opencanary runs as nobody (65534), not root', oc.Config.User === '65534:65534', oc.Config.User);
    check('OC-hardening', 'opencanary', 'opencanary: read-only FS, all caps dropped, no-new-privileges, not privileged',
      och.ReadonlyRootfs === true && (och.CapDrop ?? []).includes('ALL') && (och.SecurityOpt ?? []).includes('no-new-privileges:true') && och.Privileged === false,
      `ro=${och.ReadonlyRootfs} capdrop=${JSON.stringify(och.CapDrop)} sec=${JSON.stringify(och.SecurityOpt)}`);
    check('OC-limits', 'opencanary', 'opencanary: memory 192 MiB, 0.25 CPU, 64 PIDs', och.Memory === 201326592 && och.NanoCpus === 250000000 && och.PidsLimit === 64, `${och.Memory} ${och.NanoCpus} ${och.PidsLimit}`);
    const ocPorts = Object.values(oc.NetworkSettings.Ports ?? {}).filter(Boolean).flat();
    check('OC-ports', 'opencanary', 'opencanary publishes no host ports', ocPorts.length === 0, JSON.stringify(oc.NetworkSettings.Ports));
    const ocNets = Object.keys(oc.NetworkSettings.Networks);
    check('OC-net', 'opencanary', 'opencanary attached only to the internal lab network', ocNets.length === 1 && ocNets[0].endsWith('lab_internal'), ocNets.join(', '));
    const ocEgress = dc('exec', '-T', 'opencanary', '/opencanary/.venv/bin/python', '-c',
      "import socket\nfor h,p in (('1.1.1.1',80),('8.8.8.8',53)):\n  s=socket.socket(); s.settimeout(3)\n  try: s.connect((h,p)); print(h,'REACHED')\n  except Exception as e: print(h,'blocked',type(e).__name__)\ntry: socket.getaddrinfo('example.com',443); print('dns RESOLVED')\nexcept Exception as e: print('dns failed',type(e).__name__)");
    check('OC-egress', 'opencanary', 'opencanary cannot reach the internet or resolve external DNS', !/REACHED|RESOLVED/.test(ocEgress.out) && /blocked/.test(ocEgress.out), ocEgress.out.replace(/\n/g, ' | '));
    const PASSWORD = 'Synthetic-Pass-123';
    const touch = exec('collector', `node -e "(async()=>{const g=await fetch('http://opencanary:8081/index.html');const p=await fetch('http://opencanary:8081/index.html',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:'username=labuser&password=${PASSWORD}'});console.log('get',g.status,'post',p.status)})().catch(e=>console.log('fail',e.cause?.code??e.name))"`);
    check('OC-reachable', 'opencanary', 'opencanary HTTP decoy answers inside the lab network', /get 200/.test(touch.out), touch.out);
    await new Promise((r) => setTimeout(r, 2500));
    const adapterLogs = dc('logs', 'canary-adapter').out;
    const collectorLogs = dc('logs', 'collector').out;
    check('OC-events', 'opencanary', 'adapter normalised the page view and login attempt (logtypes 3000, 3001)', /"kind":"http.get"/.test(adapterLogs) && /"kind":"http.login-attempt"/.test(adapterLogs), adapterLogs.split('\n').filter((l) => /http\./.test(l)).slice(0, 2).join(' | ').slice(0, 400));
    check('OC-collector', 'opencanary', 'normalised OpenCanary events reached the in-lab collector', /"source":"opencanary"/.test(collectorLogs), `${(collectorLogs.match(/"source":"opencanary"/g) ?? []).length} events`);
    const canaryLogs = dc('logs', 'opencanary').out;
    const leaked = [adapterLogs, collectorLogs, canaryLogs].some((l) => l.includes(PASSWORD));
    check('OC-redaction', 'opencanary', 'submitted password appears in no lab log (opencanary, adapter, collector); only username hash + length kept', !leaked && /"passwordLength":18/.test(adapterLogs), leaked ? 'PASSWORD LEAKED' : 'redacted everywhere');
  }

  // ---------- negative control: the egress probe CAN detect connectivity ----------
  // Same image and probe on Docker's default bridge network (not the lab network).
  // Proves the ISO-egress checks are not vacuous. Makes one outbound request.
  const probeJs =
    "Promise.all(['http://1.1.1.1/','https://example.com/','https://1.1.1.1/'].map(u=>fetch(u,{signal:AbortSignal.timeout(6000),redirect:'manual'}).then(r=>u+' REACHED '+r.status).catch(e=>u+' blocked '+(e.cause?.code??e.name)))).then(x=>console.log(x.join(' ; ')))";
  const runControl = () =>
    sh('docker', [
      'run', '--rm', '--network', 'bridge', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
      'node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a',
      'node', '-e', probeJs,
    ], { timeout: 60000 });
  let ctl = runControl();
  if (!/REACHED/.test(ctl.out)) ctl = runControl();
  check('CTL-egress-probe', 'control', 'control: same probe from a non-lab network reaches the internet (probe is sensitive)', /REACHED/.test(ctl.out), ctl.out);

  // ---------- resource limits (enforced, not just configured) ----------
  const cpu = exec('honeypot', 'cat /sys/fs/cgroup/cpu.max 2>/dev/null || cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us');
  check('RES-cpu', 'resources', 'CPU quota applied in the cgroup (25000/100000)', /^25000 100000$/.test(cpu.out), cpu.out);
  const mem = exec('honeypot', `node --max-old-space-size=1024 -e "const a=[];for(;;){a.push(Buffer.alloc(16*1024*1024,1))}" 2>&1; echo rc=$?`);
  check('RES-mem', 'resources', 'allocating beyond 128 MiB is killed by the OOM killer (rc=137)', /rc=137/.test(mem.out), mem.out.split('\n').slice(-2).join(' '));
  const pids = exec('honeypot', 'i=0; while [ $i -lt 120 ]; do sleep 4 & i=$((i+1)); done 2>&1 | tail -1; echo spawned; ps | wc -l', 60000);
  check('RES-pids', 'resources', 'process creation stops at the PID limit (64)', /can't fork|Resource temporarily unavailable|fork/i.test(pids.out), pids.out.split('\n').slice(-3).join(' | '));
  await new Promise((r) => setTimeout(r, 6000)); // let the 4 s sleeps exit
  const health = exec('collector', `node -e "fetch('http://honeypot:8080/api/v1/health').then(r=>console.log('status',r.status)).catch(e=>console.log('fail',e.cause?.code??e.name))"`);
  // Any HTTP status proves the service survived; 403 also shows the earlier session termination persisted.
  check('RES-survives', 'resources', 'honeypot still answers HTTP after the limit tests', /status (200|403)/.test(health.out), health.out);

} finally {
  dc('down', '-v', '--remove-orphans');
}

const passed = checks.filter((c) => c.pass).length;
const image = sh('docker', ['image', 'inspect', 'node:22-alpine', '--format', '{{index .RepoDigests 0}}']).out;
const commit = sh('git', ['rev-parse', '--short', 'HEAD']).out;
const dirtyLab = sh('git', ['status', '--porcelain', '--', join(LAB_ROOT, 'lab')]).out;
const evidence = {
  format: 'gatra-deception-lab/lab-validation@1',
  ranAt: new Date().toISOString(),
  git: dirtyLab ? `${commit}-dirty` : commit,
  docker: info.out,
  image,
  composeProject: PROJECT,
  opencanary: WITH_CANARY,
  passed,
  total: checks.length,
  checks,
};
mkdirSync(EVIDENCE_DIR, { recursive: true });
const base = WITH_CANARY ? 'lab-validation-opencanary' : 'lab-validation';
writeFileSync(join(EVIDENCE_DIR, `${base}.json`), JSON.stringify(evidence, null, 2) + '\n');
const md = [
  '# Container lab validation evidence',
  '',
  `Generated by \`npm run deception-lab:validate-lab\` at ${evidence.ranAt}.`,
  '',
  `- Commit: ${evidence.git} (lab/ directory)`,
  `- OpenCanary profile: ${WITH_CANARY ? 'enabled for this run' : 'disabled (default)'}`,
  `- Docker: ${info.out}`,
  `- Image: ${image}`,
  `- Result: **${passed}/${checks.length} checks passed**`,
  '',
  '| Result | ID | Check | Observed |',
  '| --- | --- | --- | --- |',
  ...checks.map((c) => `| ${c.pass ? 'PASS' : 'FAIL'} | ${c.id} | ${c.description} | ${c.observed.replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 160)} |`),
  '',
];
writeFileSync(join(EVIDENCE_DIR, `${base}.md`), md.join('\n'));
console.log(`\n${passed}/${checks.length} checks passed. Evidence: docs/evidence/${base}.{json,md}`);
process.exit(passed === checks.length ? 0 : 1);
