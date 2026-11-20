/** Real local Ollama agents against a fresh, attested loopback Defense V2 stack. */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDefense } from '../../lab/services/defense/gateway.mjs';
import { createHub } from '../../lab/services/swarm/hub.mjs';
import { main, parseArgs } from './run.mjs';

const controlKey = randomBytes(32).toString('hex');
const legitKey = randomBytes(32).toString('hex');
const args = parseArgs([
  '--provider', 'ollama', '--model', 'tantular-cyber:latest',
  '--agents', '500', '--concurrency', '2',
  '--max-tool-calls', '30', '--max-model-turns', '40',
  '--max-tokens', '120000', '--max-wall-ms', '600000',
  ...process.argv.slice(2), '--control-key', controlKey, '--legit-key', legitKey,
]);
if (args.provider !== 'ollama') throw new Error('This launcher requires --provider ollama (real local inference).');
const listen = (server, port = 0) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`));
});
const close = (server) => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); });
const stackId = `local:tantular:${randomBytes(8).toString('hex')}`;
let hub;
const defense = createDefense({
  mode: 'defended', stackId, controlKey, legitimateKey: legitKey,
  peerHeader: 'x-lab-peer',
  onEvent: (event) => hub?.ingest({ source: 'defense', event }),
});
const gateway = createServer(defense.publicHandler);
try {
  const upstream = await listen(gateway);
  hub = createHub({ upstream });
  const origin = await listen(hub.server, 18092);
  console.log(`Local model swarm: ${args.agents} agents, concurrency ${args.concurrency}, model ${args.model}. Hub: ${origin}`);
  console.log('Actual Ollama inference; no scripted role plans. Local gateway + hub; no Docker/GCP/OpenCanary container.');
  const result = await main({ ...args, target: origin, hub: origin, basePath: '/lab', expectMode: 'defended', expectStack: stackId });
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const evidenceDir = join(root, 'docs/evidence');
  mkdirSync(evidenceDir, { recursive: true });
  const note = join(evidenceDir, `${new Date().toISOString().replace(/[:.]/g, '-')}-tantular-model-swarm.md`);
  writeFileSync(note, [
    '# Local Tantular model swarm', '',
    `Model: ${args.model}. Provider: Ollama. Independent conversations: ${args.agents}. Concurrency: ${args.concurrency}.`, '',
    'All roles, including legitimate clients, use actual model inference. No scripted plans execute. Agents share a synthetic target but have no inter-agent memory or coordination.', '',
    'Scope: loopback Defense V2 gateway and hub. No GCP, IAP, Docker, or OpenCanary container tested. Per-agent budgets start upon admission, after queueing. This is one exploratory engagement, not a matched defense comparison.', '',
    `Result: ${result.outPath}`, `Journal: ${result.journalPath}`, '',
    'Read validity and efficacy before interpreting outcomes; budget exits and model failures are not proof of defense effectiveness.', '',
    '```json', JSON.stringify(result.summary, null, 2), '```', '',
  ].join('\n'));
  console.log(`Evidence: ${note}`);
} finally {
  if (hub?.server.listening) await close(hub.server);
  if (gateway.listening) await close(gateway);
}
