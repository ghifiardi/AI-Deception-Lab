/**
 * Read-only pre-test check: does the stack behind the tunnel attest, under
 * this engagement's control key, the expected GCP stack id and defense mode?
 * Writes nothing, starts no agent, calls no model.
 *
 * Keys come from the VM's key file on stdin (never from arguments), e.g.
 *   gcloud compute ssh NAME … --command='sudo cat /tmp/gatra-swarm-keys.env' \
 *     | node experiments/swarm/attest.mjs --expect-mode defended
 * The expected stack id defaults to LAB_STACK_ID from that same file and must
 * be a GCP stack id (gcp:<host>:<8 hex>); missing or other labels are NO-GO.
 * Exit 0 = GO, 1 = NO-GO.
 */
import { readFileSync } from 'node:fs';
import { attestStack, enforceAttestation } from './run.mjs';
import { requireGcpStackId } from './stack-id.mjs';
import { installEgressGuard } from '../../lab/services/egress-guard.mjs';

/**
 * @param {string} keyFileText the VM key file
 * @param {{ target?: string, basePath?: string, expectMode?: string, expectStack?: string }} [opts]
 * @param {{ fetchImpl?: typeof fetch }} [deps]
 * @returns {Promise<{ go: boolean, message: string }>}
 */
export async function checkReadiness(keyFileText, opts = {}, deps = {}) {
  const args = { target: 'http://127.0.0.1:18092', basePath: '/lab', expectMode: 'defended', ...opts };
  const env = {};
  for (const line of String(keyFileText).split(/\r?\n/)) {
    const m = /^(LAB_CONTROL_KEY|LAB_STACK_ID)=(.+)$/.exec(line.trim());
    if (m) env[m[1]] = m[2];
  }
  if (!env.LAB_CONTROL_KEY || env.LAB_CONTROL_KEY.length < 32) return { go: false, message: 'NO-GO: no LAB_CONTROL_KEY on stdin (pipe the VM key file in)' };
  args.expectStack ??= env.LAB_STACK_ID;
  try { requireGcpStackId(args.expectStack, opts.expectStack ? '--expect-stack' : 'VM key file LAB_STACK_ID'); } catch (err) { return { go: false, message: `NO-GO: ${err.message}` }; }
  const guard = installEgressGuard({ allowHosts: [] });
  let att;
  try { att = await attestStack({ ...args, controlKey: env.LAB_CONTROL_KEY }, deps); } finally { guard.uninstall(); }
  try {
    enforceAttestation(att, args);
  } catch (err) {
    return { go: false, message: `NO-GO: ${err.message}` };
  }
  return { go: true, message: `GO: stack ${att.stackId} attests DEFENSE_MODE=${att.mode} at ${att.issuedAt}` };
}

if (process.argv[1]?.endsWith('/swarm/attest.mjs')) {
  const opts = {};
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--target') opts.target = argv[++i];
    else if (a === '--base-path') opts.basePath = argv[++i];
    else if (a === '--expect-mode') opts.expectMode = argv[++i];
    else if (a === '--expect-stack') opts.expectStack = argv[++i];
    else { console.error(`unknown argument ${a}`); process.exit(2); }
  }
  const { go, message } = await checkReadiness(readFileSync(0, 'utf8'), opts);
  (go ? console.log : console.error)(message);
  process.exit(go ? 0 : 1);
}
