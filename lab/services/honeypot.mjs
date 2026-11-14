// Container entry: serves the lab target (target.mjs) on :8080 inside the
// internal network and forwards every target event to the in-lab collector.
import { createServer } from 'node:http';
import { createTarget, httpListener } from './target.mjs';

const COLLECTOR = process.env.COLLECTOR_URL ?? 'http://collector:4318/v1/events';
const MODE = /** @type {'none'|'static'|'adaptive'} */ (process.env.LAB_MODE ?? 'static');
const SEED = Number(process.env.LAB_SEED ?? 42);

const forward = (event) => {
  const line = JSON.stringify({ sensor: 'honeypot', mode: MODE, ...event });
  console.log(line);
  fetch(COLLECTOR, { method: 'POST', headers: { 'content-type': 'application/json' }, body: line, signal: AbortSignal.timeout(2000) }).catch(() =>
    console.log(JSON.stringify({ sensor: 'honeypot', warn: 'collector unreachable' })),
  );
};

const target = createTarget({ mode: MODE, seed: SEED, onEvent: forward });
createServer(httpListener(target)).listen(8080, () => console.log(JSON.stringify({ sensor: 'honeypot', listening: 8080, mode: MODE })));
