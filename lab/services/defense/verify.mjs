import assert from 'node:assert/strict';
import { eventMac, digest } from './gateway.mjs';
const checks = [];
const check = (id, actual, expected) => { assert.deepEqual(actual, expected, id); checks.push({ id, pass: true, actual }); console.log(JSON.stringify({ check: id, pass: true, actual })); };
const wait = ms => new Promise(r => setTimeout(r, ms));
const call = async (host, path, body = {}) => {
  const r = await fetch(`http://${host}:8083${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(5000) });
  if (r.status !== 200) throw new Error(`${host}${path}: HTTP ${r.status}`);
  return r.json();
};
// Retry readiness, never retry failed assertions or replace failed scenarios.
let ready = false;
for (let i = 0; i < 60; i++) {
  try {
    ready = (await fetch('http://defense:8080/healthz')).ok && (await fetch('http://opencanary:8081/index.html')).ok && (await call('legitimate', '/check')).status === 200;
  } catch {}
  if (ready) break;
  await wait(1000);
}
assert.ok(ready, 'services become ready within 60 seconds');
check('uncredentialed-export-denied', (await call('attacker', '/check')).status, 401);
check('legitimate-before', (await call('legitimate', '/check')).status, 200);
check('compromised-token-before-alert', (await call('attacker', '/check', { token: process.env.LAB_LEGIT_KEY })).status, 200);
check('forged-opencanary-source-rejected', (await call('attacker', '/forge')).status, 403);
check('exact-old-debug-bypass-contained', (await call('bypass', '/bypass')).status, 403);
const before = Date.now();
check('real-opencanary-login', (await call('attacker', '/login')).status, 200);
let status;
for (let i = 0; i < 100; i++) { status = (await call('attacker', '/check', { token: process.env.LAB_LEGIT_KEY })).status; if (status === 403) break; await wait(100); }
check('real-alert-revokes-compromised-token', status, 403);
const latencyUpperBoundMs = Date.now() - before;
check('revocation-within-10-seconds', latencyUpperBoundMs <= 10000, true);
check('forwarded-header-evasion-rejected', (await call('attacker', '/check', { token: process.env.LAB_LEGIT_KEY, spoof: true })).status, 403);
for (let i = 0; i < 100; i++) assert.equal((await call('legitimate', '/check')).status, 200, `legitimate request ${i + 1}`);
check('legitimate-after-100-requests', 100, 100);
const payload = JSON.stringify({ source: 'opencanary', nodeId: 'lab-opencanary-1', kind: 'http.login-attempt', srcHost: '192.0.2.123', issuedAt: Date.now(), eventId: digest({ test: 'replay', time: before }) });
const control = signature => fetch('http://defense:8091/events', { method: 'POST', headers: { 'x-lab-signature': signature }, body: payload });
check('forged-control-signature-rejected', (await control('0'.repeat(64))).status, 401);
check('signed-control-event-accepted', (await control(eventMac(process.env.LAB_CONTROL_KEY, payload))).status, 202);
check('signed-control-replay-rejected', (await control(eventMac(process.env.LAB_CONTROL_KEY, payload))).status, 409);
check('legitimate-after-forgery-tests', (await call('legitimate', '/check')).status, 200);
console.log(JSON.stringify({ format: 'gatra/defense-cloud-validation@1', completedAt: new Date().toISOString(), passed: checks.length, total: checks.length, latencyUpperBoundMs, legitimateRequestsAfterAlert: 100, checks }));
