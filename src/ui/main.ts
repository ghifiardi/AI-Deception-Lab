import '../styles.css';
import { compareModes } from '../engine/metrics.ts';
import { DEFAULT_POLICY } from '../engine/policy.ts';
import type { PolicyConfig } from '../engine/policy.ts';
import { SCENARIOS } from '../engine/scenarios.ts';
import { compileRun } from '../engine/simulator.ts';
import { verifyChain } from '../engine/hash.ts';
import type { CompiledRun } from '../engine/simulator.ts';
import { deriveState } from '../engine/state.ts';
import type { AnalystDecision, AnalystInput, DeceptionMode, LabEvent, ScenarioId } from '../engine/types.ts';
import { DEMO_SEED, DEMO_SHOTS, matchCue } from './director.ts';
import type { Cue } from './director.ts';
import { Timeline, h, renderDecisionPanel, renderEconomics, renderPolicy } from './panels.ts';
import { bundledExperiments, renderExperiments } from './experiments.ts';
import type { ExperimentResult } from './experiments.ts';
import { Topology } from './topology.ts';
import { initLive } from './live.ts';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

/** Gaps longer than this (sim ms) play faster, e.g. waiting for an analyst. */
const LONG_GAP_MS = 2500;
const LONG_GAP_RATE = 5;

interface App {
  scenario: ScenarioId;
  mode: DeceptionMode;
  seed: number;
  speed: number;
  playing: boolean;
  policy: PolicyConfig;
  policyModified: boolean;
  run: CompiledRun;
  count: number;
  clock: number;
  analystMode: 'scripted' | 'interactive';
  analystInputs: AnalystInput[];
  /** Demo mode: playback pauses until this time (ms, performance.now) so captions can be read. */
  holdUntil: number;
  onReveal?: (e: LabEvent) => void;
}

/** How long demo playback holds on each narrated event. */
const CAPTION_DWELL_MS = 3200;

const params = new URLSearchParams(location.search);
const scenarioParam = params.get('scenario') as ScenarioId | null;
const modeParam = params.get('mode') as DeceptionMode | null;

const app: App = {
  scenario: SCENARIOS.some((s) => s.id === scenarioParam) ? scenarioParam! : 'api-canary',
  mode: modeParam && ['none', 'static', 'adaptive'].includes(modeParam) ? modeParam : 'adaptive',
  seed: Number.parseInt(params.get('seed') ?? '', 10) || DEMO_SEED,
  speed: Number(params.get('speed')) || 1,
  playing: false,
  policy: structuredClone(DEFAULT_POLICY),
  policyModified: false,
  run: undefined as unknown as CompiledRun,
  count: 0,
  clock: 0,
  holdUntil: 0,
  analystMode: params.get('analyst') === 'interactive' ? 'interactive' : 'scripted',
  analystInputs: [],
};

const topology = new Topology($('topology'));
const timeline = new Timeline($('timeline'));

/* ---------------- controls ---------------- */

const scenarioSel = $<HTMLSelectElement>('scenario');
for (const s of SCENARIOS) scenarioSel.append(h('option', { value: s.id }, s.title));
scenarioSel.value = app.scenario;
scenarioSel.addEventListener('change', () => {
  app.scenario = scenarioSel.value as ScenarioId;
  recompile();
});

const modeButtons = [...document.querySelectorAll<HTMLButtonElement>('[data-mode]')];
for (const b of modeButtons) {
  b.addEventListener('click', () => {
    app.mode = b.dataset.mode as DeceptionMode;
    recompile();
  });
}

const analystButtons = [...document.querySelectorAll<HTMLButtonElement>('[data-analyst]')];
for (const b of analystButtons) {
  b.addEventListener('click', () => {
    app.analystMode = b.dataset.analyst as App['analystMode'];
    app.analystInputs = [];
    recompile();
  });
}

const seedInput = $<HTMLInputElement>('seed');
seedInput.value = String(app.seed);
seedInput.addEventListener('change', () => {
  app.seed = Math.max(1, Math.min(2 ** 31 - 1, Number.parseInt(seedInput.value, 10) || 1));
  seedInput.value = String(app.seed);
  recompile();
});

const speedSel = $<HTMLSelectElement>('speed');
speedSel.value = String(app.speed);
if (speedSel.value !== String(app.speed)) speedSel.value = '1';
speedSel.addEventListener('change', () => (app.speed = Number(speedSel.value)));

const playBtn = $<HTMLButtonElement>('play');
const scrub = $<HTMLInputElement>('scrub');
const clockEl = $('clock');

playBtn.addEventListener('click', () => setPlaying(!app.playing));
$('step').addEventListener('click', () => step());
$('back').addEventListener('click', () => seek(app.count - 1));
$('reset').addEventListener('click', () => reset());
scrub.addEventListener('input', () => {
  setPlaying(false);
  seek(Number(scrub.value));
});

document.querySelectorAll<HTMLButtonElement>('[role="tab"]').forEach((tab) =>
  tab.addEventListener('click', () => {
    document.querySelectorAll<HTMLButtonElement>('[role="tab"]').forEach((t) => {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      $(t.getAttribute('aria-controls')!).hidden = !on;
    });
  }),
);

document.addEventListener('keydown', (ev) => {
  const tag = (ev.target as HTMLElement).tagName;
  if (['INPUT', 'SELECT', 'TEXTAREA'].includes(tag) && ev.key !== 'Escape') return;
  if (ev.key === 'Escape' && demo.active) return stopDemo();
  if (demo.active) return;
  if (ev.key === ' ') {
    ev.preventDefault();
    setPlaying(!app.playing);
  } else if (ev.key === 'ArrowRight') step();
  else if (ev.key === 'ArrowLeft') seek(app.count - 1);
  else if (ev.key.toLowerCase() === 'r') reset();
});

/* ---------------- run lifecycle ---------------- */

function recompile() {
  setPlaying(false);
  app.analystInputs = [];
  app.run = compileRun({ scenario: app.scenario, mode: app.mode, seed: app.seed, policy: app.policy, analyst: analystConfig() });
  scenarioSel.value = app.scenario;
  modeButtons.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === app.mode)));
  analystButtons.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.analyst === app.analystMode)));
  const att = app.run.fixture.attacker;
  topology.setActors(att.kind === 'benign-scanner' ? 'scanner' : 'attacker', att.instrumented);
  topology.setDecoysVisible(app.mode !== 'none');
  $('summary').textContent = app.run.fixture.summary;
  scrub.max = String(app.run.events.length);
  renderEconomics($('econ'), compareModes(app.scenario, app.seed, app.policy), app.run);
  renderPolicyPanel();
  syncUrl();
  reset();
}

function analystConfig() {
  return app.analystMode === 'interactive' ? { mode: 'interactive' as const, inputs: app.analystInputs } : { mode: 'scripted' as const };
}

/** Record a human decision as an explicit input, recompile, and continue from the same point. */
function decide(ruleId: string, decision: AnalystDecision) {
  const revealed = app.run.events.slice(0, app.count);
  const req = [...revealed].reverse().find((e) => e.kind === 'approval.requested' && e.ruleId === ruleId);
  if (!req) return;
  const atT = Math.max(app.clock, req.t) + 1;
  const note = { approve: 'Approved in the lab UI', reject: 'Rejected in the lab UI', observe: 'Keep observing' }[decision];
  const headBefore = revealed.at(-1)?.hash;
  app.analystInputs = [...app.analystInputs, { ruleId, decision, atT, note }];
  app.run = compileRun({ scenario: app.scenario, mode: app.mode, seed: app.seed, policy: app.policy, analyst: analystConfig() });
  scrub.max = String(app.run.events.length);
  // Decisions only add events after atT, so the revealed prefix must be unchanged.
  if (app.run.events[app.count - 1]?.hash !== headBefore) {
    timeline.reset();
    app.count = 0;
    app.clock = 0;
  }
  renderEconomics($('econ'), compareModes(app.scenario, app.seed, app.policy), app.run);
  render();
  setPlaying(true);
}

function exportRun() {
  const doc = {
    format: 'gatra-deception-lab/run-export@1',
    hashAlgorithm: 'sha256',
    exportedAt: new Date().toISOString(),
    scenario: app.scenario,
    mode: app.mode,
    seed: app.seed,
    policy: app.policy,
    analyst: analystConfig(),
    chainHead: app.run.events.at(-1)?.hash,
    events: app.run.events,
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 1)], { type: 'application/json' }));
  const a = h('a', { href: url, download: `deception-lab-${app.scenario}-${app.mode}-seed${app.seed}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('export').addEventListener('click', exportRun);

let experiments: ExperimentResult[] = bundledExperiments();
let selectedExperiment = 0;
function renderExperimentsPanel() {
  renderExperiments(
    $('experiments'),
    experiments,
    selectedExperiment,
    (i) => {
      selectedExperiment = i;
      renderExperimentsPanel();
    },
    (r) => {
      experiments = [r, ...experiments];
      selectedExperiment = 0;
      renderExperimentsPanel();
    },
  );
}
renderExperimentsPanel();

// The Live tab is the only networked panel: build it once, and only when the
// operator opens it, so the offline demo never tries to reach a hub.
let liveStarted = false;
$('tab-live').addEventListener('click', () => {
  if (liveStarted) return;
  liveStarted = true;
  initLive($('live'));
});

function renderPolicyPanel() {
  renderPolicy(
    $('policy'),
    app.policy,
    app.policyModified,
    (id, enabled) => {
      app.policy.rules = app.policy.rules.map((r) => (r.id === id ? { ...r, enabled } : r));
      app.policyModified = JSON.stringify(app.policy) !== JSON.stringify(DEFAULT_POLICY);
      recompile();
    },
    () => {
      app.policy = structuredClone(DEFAULT_POLICY);
      app.policyModified = false;
      recompile();
    },
  );
}

function syncUrl() {
  if (demo.active) return;
  const q = new URLSearchParams({ scenario: app.scenario, mode: app.mode, seed: String(app.seed) });
  if (app.analystMode === 'interactive') q.set('analyst', 'interactive');
  history.replaceState(null, '', `?${q}`);
}

function reset() {
  setPlaying(false);
  app.holdUntil = 0;
  app.count = 0;
  app.clock = 0;
  topology.clearPackets();
  timeline.reset();
  render();
}

function seek(count: number) {
  app.count = Math.max(0, Math.min(app.run.events.length, count));
  app.clock = app.run.events[app.count - 1]?.t ?? 0;
  topology.clearPackets();
  render();
}

function step() {
  setPlaying(false);
  const e = app.run.events[app.count];
  if (!e) return;
  app.clock = e.t;
  reveal(e);
  app.count++;
  render();
}

function reveal(e: LabEvent) {
  topology.animate(e, Math.max(220, 650 / Math.max(app.speed, 0.5)));
  app.onReveal?.(e);
  // Human in the loop: stop and wait for a decision (it becomes an explicit event).
  if (app.analystMode === 'interactive' && e.kind === 'approval.requested') {
    setPlaying(false);
  }
}

function setPlaying(on: boolean) {
  if (on && app.count >= app.run.events.length) {
    app.count = 0;
    app.clock = 0;
    timeline.reset();
  }
  app.playing = on;
  playBtn.textContent = on ? 'Pause' : app.count >= app.run?.events.length ? 'Replay' : 'Play';
  playBtn.setAttribute('aria-pressed', String(on));
  if (on) lastFrame = performance.now();
}

let fastForward = false;
function render() {
  const s = deriveState(app.run, app.count);
  topology.render(s);
  timeline.render(app.run, app.count);
  renderDecisionPanel($('decision'), app.run, s, {
    interactive: app.analystMode === 'interactive',
    inputs: app.analystInputs,
    onDecide: (ruleId, decision) => {
      decide(ruleId, decision);
    },
  });
  scrub.value = String(app.count);
  scrub.setAttribute('aria-valuetext', `Event ${app.count} of ${app.run.events.length}`);
  clockEl.textContent = `T+${(app.clock / 1000).toFixed(1)}s · event ${app.count}/${app.run.events.length}${fastForward ? ' · skipping a long wait' : ''}`;
  const shown = app.run.events.slice(0, app.count);
  const chainOk = verifyChain(shown).ok;
  $('chain').textContent = app.count
    ? `SHA-256 chain ${chainOk ? 'verified' : 'BROKEN'} · head ${app.run.events[app.count - 1]!.hash.slice(0, 16)}…`
    : 'Chain empty';
  $('chain').title = app.count ? app.run.events[app.count - 1]!.hash : '';
  if (!app.playing) playBtn.textContent = app.count >= app.run.events.length ? 'Replay' : 'Play';
}

let lastFrame = performance.now();
let lastRender = 0;
function frame(now: number) {
  const dt = Math.min(100, now - lastFrame);
  lastFrame = now;
  if (app.playing) {
    const events = app.run.events;
    const next = events[app.count];
    if (!next) {
      setPlaying(false);
      render();
    } else {
      const holding = now < app.holdUntil;
      fastForward = !holding && next.t - app.clock > LONG_GAP_MS;
      if (!holding) app.clock += dt * app.speed * (fastForward ? LONG_GAP_RATE : 1);
      let changed = false;
      while (app.playing && app.count < events.length && events[app.count]!.t <= app.clock && performance.now() >= app.holdUntil) {
        reveal(events[app.count]!);
        app.count++;
        changed = true;
      }
      if (changed || now - lastRender > 200) {
        lastRender = now;
        render();
      }
    }
  }
  requestAnimationFrame(frame);
}

/* ---------------- demo mode ---------------- */

interface DemoState {
  active: boolean;
  token: number;
}
const demo: DemoState = { active: false, token: 0 };
declare global {
  interface Window {
    __demo?: { status: 'idle' | 'running' | 'done' | 'stopped'; shot: number; totalShots: number };
  }
}
window.__demo = { status: 'idle', shot: 0, totalShots: DEMO_SHOTS.length };

const overlay = $('overlay');
const caption = $('caption');

const wait = (ms: number, token: number) =>
  new Promise<void>((resolve, reject) => {
    setTimeout(() => (token === demo.token ? resolve() : reject(new Error('demo cancelled'))), ms);
  });

function resetWatermark() {
  $('watermark').textContent = 'SIMULATED · synthetic events only · no outbound connections';
  $('watermark').classList.remove('measured');
}

function setCaption(text: string) {
  caption.textContent = text;
  caption.hidden = !text;
}

async function runDemo() {
  const token = ++demo.token;
  demo.active = true;
  document.body.classList.add('demo');
  window.__demo = { status: 'running', shot: 0, totalShots: DEMO_SHOTS.length };
  const savedSpeed = app.speed;
  try {
    for (let i = 0; i < DEMO_SHOTS.length; i++) {
      const shot = DEMO_SHOTS[i]!;
      window.__demo.shot = i + 1;
      overlay.hidden = true;
      overlay.replaceChildren();
      if (shot.type === 'card') {
        setCaption('');
        overlay.append(h('div', { class: 'card-shot' }, h('h2', {}, shot.title), ...shot.body.map((b) => h('p', {}, b))));
        overlay.hidden = false;
        topology.camera('all', 0);
        await wait(shot.ms, token);
      } else if (shot.type === 'tour') {
        app.scenario = 'api-canary';
        app.mode = 'adaptive';
        app.seed = DEMO_SEED;
        recompile();
        for (const stop of shot.stops) {
          topology.camera(stop.camera);
          setCaption(stop.caption);
          await wait(stop.ms, token);
        }
      } else if (shot.type === 'experiments') {
        setCaption(shot.caption);
        $('watermark').textContent = 'MEASURED · live runs on a local mock lab target · not production';
        $('watermark').classList.add('measured');
        const panel = h('div', { class: 'compare-shot' });
        renderExperiments(panel, experiments, 0, () => {}, () => {});
        panel.querySelectorAll('.exp-head select, .exp-head label, details, .comparisons .footnote').forEach((n) => n.remove());
        overlay.append(panel);
        overlay.hidden = false;
        await wait(shot.ms, token);
        resetWatermark();
      } else if (shot.type === 'run') {
        app.scenario = shot.scenario;
        app.mode = shot.mode;
        app.seed = DEMO_SEED;
        app.analystMode = shot.analyst ? 'interactive' : 'scripted';
        recompile();
        app.speed = shot.speed;
        topology.camera('all', 600);
        const counts = new Map<string, number>();
        const fired = new Set<Cue>();
        const auto = shot.analyst;
        app.onReveal = (e) => {
          if (auto && e.kind === 'approval.requested' && e.ruleId === auto.ruleId) {
            setTimeout(() => token === demo.token && decide(auto.ruleId, auto.decision), auto.afterMs);
          }
          const cue = matchCue(shot.cues, e, counts, fired);
          if (!cue) return;
          fired.add(cue);
          setCaption(cue.caption);
          if (cue.camera) topology.camera(cue.camera);
          app.holdUntil = performance.now() + CAPTION_DWELL_MS;
        };
        setPlaying(true);
        while (app.count < app.run.events.length) await wait(200, token);
        app.onReveal = undefined;
        await wait(3500, token);
      } else {
        app.scenario = shot.scenario;
        app.mode = shot.mode;
        app.seed = DEMO_SEED;
        recompile();
        seek(app.run.events.length);
        const panel = h('div', { class: 'compare-shot' });
        renderEconomics(panel, compareModes(shot.scenario, DEMO_SEED, app.policy), app.run);
        overlay.append(panel);
        overlay.hidden = false;
        setCaption(shot.caption);
        await wait(shot.ms, token);
      }
    }
    window.__demo.status = 'done';
  } catch {
    window.__demo.status = 'stopped';
  } finally {
    if (token === demo.token) {
      resetWatermark();
      app.onReveal = undefined;
      app.holdUntil = 0;
      app.analystMode = 'scripted';
      app.speed = savedSpeed;
      overlay.hidden = true;
      setCaption('');
      topology.camera('all', 600);
      document.body.classList.remove('demo');
      demo.active = false;
    }
  }
}

function stopDemo() {
  demo.token++;
  resetWatermark();
  app.onReveal = undefined;
  app.holdUntil = 0;
  setPlaying(false);
  overlay.hidden = true;
  setCaption('');
  document.body.classList.remove('demo');
  topology.camera('all', 0);
  demo.active = false;
  if (window.__demo) window.__demo.status = 'stopped';
  syncUrl();
}

$('demo').addEventListener('click', () => void runDemo());
$('exit-demo').addEventListener('click', () => stopDemo());

/* ---------------- boot ---------------- */

recompile();
requestAnimationFrame(frame);
if (params.get('demo') === '1') void runDemo();
else if (params.get('autoplay') === '1') setPlaying(true);
