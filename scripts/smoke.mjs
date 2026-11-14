// UI smoke test: every scenario is playable, resettable and offline.
// Run: npm run deception-lab:smoke   (add --screens to refresh docs/screenshots)
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { LAB_ROOT, guardNetwork, launchBrowser, startServer } from './browser.mjs';

const screens = process.argv.includes('--screens');
const shotDir = join(LAB_ROOT, 'docs', 'screenshots');
if (screens) await mkdir(shotDir, { recursive: true });

const { server, url } = await startServer();
const browser = await launchBrowser();
const violations = [];
const errors = [];
let failed = false;

async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed = true;
    console.error(`  FAIL ${name}\n       ${String(err?.message ?? err).split('\n').join('\n       ')}`);
  }
}

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  guardNetwork(page, violations);
  page.on('pageerror', (e) => errors.push(String(e)));
  // Expected: with no swarm hub running, the Live tab's /hub proxy answers 500. Anything else counts.
  page.on('console', (m) => m.type() === 'error' && !/\/hub\/(state|stream)$/.test(m.location().url) && errors.push(m.text()));

  const runToEnd = async () => {
    const total = Number(await page.locator('#scrub').getAttribute('max'));
    for (let i = 0; i < total; i++) await page.click('#step');
    return total;
  };
  const kinds = () => page.$$eval('#timeline li', (els) => els.map((e) => e.getAttribute('data-kind')));

  await page.goto(`${url}?scenario=api-canary&mode=adaptive&seed=42`);
  await page.waitForSelector('svg [data-node="hp-api"]');

  await check('SIMULATED badge and watermark are visible', async () => {
    assert.equal(await page.locator('.sim-badge').innerText(), 'SIMULATED');
    assert.ok(await page.locator('.watermark').isVisible());
  });

  await check('play advances, pause stops, reset clears', async () => {
    await page.selectOption('#speed', '4');
    await page.click('#play');
    await page.waitForFunction(() => document.querySelectorAll('#timeline li').length >= 4);
    await page.click('#play');
    const n = (await kinds()).length;
    await page.waitForTimeout(600);
    assert.equal((await kinds()).length, n, 'paused playback must not advance');
    await page.click('#reset');
    assert.equal((await kinds()).length, 0);
    await page.click('#step');
    await page.click('#step');
    assert.equal((await kinds()).length, 2);
    await page.click('#back');
    assert.equal((await kinds()).length, 1);
    await page.click('#reset');
  });

  await check('scenario a: canary use produces evidence and a containment decision', async () => {
    const total = await runToEnd();
    const k = await kinds();
    assert.equal(k.length, total);
    assert.ok(k.includes('canary.used'));
    assert.ok(k.includes('containment.result'));
    const side = await page.locator('#decision').innerText();
    assert.match(side, /R-CANARY-01/);
    assert.match(side, /EV-A-\d{3}/);
    assert.match(side, /Contained/);
    assert.match(await page.locator('#econ').innerText(), /Unavailable/);
    if (screens) await page.screenshot({ path: join(shotDir, 'desktop-api-canary.png') });
  });

  await check('replay with the same seed gives the same chain head', async () => {
    const head1 = await page.locator('#chain').innerText();
    await page.click('#reset');
    await runToEnd();
    assert.equal(await page.locator('#chain').innerText(), head1);
  });

  for (const [scenario, mode, expect] of [
    ['false-positive', 'static', /R-SAFE-00[\s\S]*Rejected by analyst/],
    ['agentic-decoy', 'adaptive', /Stopped by harness|Contained/],
    ['egress-block', 'adaptive', /R-EGRESS-01/],
  ]) {
    await check(`scenario ${scenario}/${mode} plays to the end`, async () => {
      await page.selectOption('#scenario', scenario);
      await page.click(`[data-mode="${mode}"]`);
      await runToEnd();
      assert.match(await page.locator('#decision').innerText(), expect);
      const k = await kinds();
      assert.equal(k.at(-1), 'scenario.end');
      if (scenario === 'egress-block') assert.equal(k.filter((x) => x === 'egress.denied').length, 3);
      const econ = await page.locator('#econ').innerText();
      if (scenario === 'agentic-decoy') assert.doesNotMatch(econ, /Unavailable/);
      else assert.match(econ, /Unavailable/);
      if (screens) await page.screenshot({ path: join(shotDir, `desktop-${scenario}.png`) });
    });
  }

  await check('policy toggle recompiles: disabling R-SAFE-00 disrupts the scanner', async () => {
    await page.selectOption('#scenario', 'false-positive');
    await page.click('#tab-policy');
    await page.uncheck('#rule-R-SAFE-00');
    await runToEnd();
    assert.match(await page.locator('#decision').innerText(), /R-DECOY-01/);
    await page.click('text=Restore default policy');
    await page.click('#tab-econ');
  });

  await check('interactive analyst: playback pauses for a human; Reject is recorded as an event and playback resumes', async () => {
    await page.goto(`${url}?scenario=false-positive&mode=static&seed=42&analyst=interactive`);
    await page.waitForSelector('svg');
    await page.selectOption('#speed', '4');
    await page.click('#play');
    await page.waitForSelector('[data-decide="reject"]', { timeout: 20000 });
    assert.equal(await page.locator('#play').getAttribute('aria-pressed'), 'false', 'paused while awaiting decision');
    if (screens) await page.screenshot({ path: join(shotDir, 'interactive-decision.png') });
    await page.click('[data-decide="reject"]');
    await page.waitForFunction(() => [...document.querySelectorAll('#timeline li')].some((li) => li.getAttribute('data-kind') === 'approval.denied'), null, { timeout: 20000 });
    await page.waitForFunction(() => document.querySelector('#timeline li:last-child')?.getAttribute('data-kind') === 'scenario.end', null, { timeout: 30000 });
    const side = await page.locator('#decision').innerText();
    assert.match(side, /Rejected by analyst/);
    assert.match(side, /Your decisions[\s\S]*R-SAFE-00 reject/);
    assert.match(await page.locator('#chain').innerText(), /SHA-256 chain verified/);
  });

  await check('export run: CLI verifier validates the SHA-256 chain and replays it identically', async () => {
    const [download] = await Promise.all([page.waitForEvent('download'), page.click('#export')]);
    const file = join(tmpdir(), `lab-export-${process.pid}.json`);
    await download.saveAs(file);
    const r = spawnSync(process.execPath, ['--experimental-strip-types', '--no-warnings', join(LAB_ROOT, 'scripts', 'verify-log.ts'), file, '--replay'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /VALID/);
    assert.match(r.stdout, /Replay: IDENTICAL/);
  });

  await check('experiments tab: measured results, outcome classes, comparisons, provenance chips, Ed25519 verified in browser', async () => {
    assert.match(await page.locator('#econ').innerText(), /Synthetic/);
    await page.click('#tab-experiments');
    // Select the pre-registered run explicitly: newer ad-hoc result files may sort first.
    const m2 = await page.locator('#exp-pick option', { hasText: 'M2-TC-v1' }).getAttribute('value');
    await page.selectOption('#exp-pick', m2);
    const exp = await page.locator('#experiments').innerText();
    assert.match(exp, /Measured/);
    assert.match(exp, /run logs verified/);
    assert.match(exp, /Contained by the lab/);
    assert.match(exp, /Comparisons between modes/);
    assert.match(exp, /Exploratory|Validated/);
    // Default view is the pre-registered Tantular Cyber run: only registered hypotheses can validate.
    assert.match(exp, /tantular-cyber:latest/);
    assert.match(exp, /H1: inconclusive/);
    assert.match(exp, /post hoc/);
    assert.equal(await page.locator('#experiments .badge-validated').count(), 0);
    await page.waitForSelector('[data-signature="valid"]', { timeout: 20000 });
    assert.match(await page.locator('[data-signature]').innerText(), /verified in this browser/);
    assert.match(exp, /Egress attempts blocked: 0/);
    if (screens) await page.locator('.tabs').screenshot({ path: join(shotDir, 'experiments-tab.png') });
    // The scripted control has no model: tokens must read Unavailable, never 0.
    const scripted = await page.locator('#exp-pick option', { hasText: 'Scripted control agent (deterministic), 5 trials, M2 format' }).getAttribute('value');
    await page.selectOption('#exp-pick', scripted);
    const ctl = await page.locator('#experiments').innerText();
    assert.match(ctl, /Unavailable/);
    assert.match(ctl, /No model in the loop/);
    await page.click('#tab-econ');
  });

  await check('live tab: one panel, honest empty state without a hub, non-loopback URLs refused', async () => {
    await page.click('#tab-live');
    await page.waitForFunction(() => /no engagement|live/.test(document.querySelector('[data-live-status]')?.textContent ?? ''), null, { timeout: 8000 });
    // Re-selecting experiments must not duplicate the Live panel.
    await page.click('#tab-experiments');
    await page.selectOption('#exp-pick', { index: 1 });
    await page.click('#tab-live');
    assert.equal(await page.locator('#live .live-url').count(), 1);
    await page.fill('#live .live-url', 'https://example.com');
    await page.click('#live .live-controls button');
    assert.match(await page.locator('[data-live-status]').innerText(), /refused/);
    await page.click('#tab-econ');
  });

  await check('phone width: no horizontal scroll', async () => {
    const phone = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
    guardNetwork(phone, violations);
    await phone.goto(`${url}?scenario=egress-block&mode=adaptive&seed=42`);
    await phone.waitForSelector('svg');
    for (let i = 0; i < 20; i++) await phone.click('#step');
    const overflow = await phone.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 0, `page overflows by ${overflow}px`);
    if (screens) await phone.screenshot({ path: join(shotDir, 'mobile-egress-block.png'), fullPage: false });
    await phone.close();
  });

  await check('demo mode starts and can be exited', async () => {
    await page.goto(`${url}?scenario=api-canary`);
    await page.click('#demo');
    await page.waitForFunction(() => window.__demo?.status === 'running');
    await page.waitForSelector('.card-shot');
    if (screens) {
      await page.waitForTimeout(400);
      await page.screenshot({ path: join(shotDir, 'demo-title.png') });
    }
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => window.__demo?.status === 'stopped');
    assert.equal(await page.locator('body.demo').count(), 0);
  });

  await check('no outbound (non-loopback) requests were made', async () => {
    assert.deepEqual(violations, []);
  });
  await check('no page errors', async () => {
    assert.deepEqual(errors, []);
  });
} finally {
  await browser.close();
  await server.close();
}

if (failed) {
  console.error('\nSmoke test FAILED');
  process.exit(1);
}
console.log('\nSmoke test passed');
