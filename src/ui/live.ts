/**
 * Live engagement tab: real-time view of a swarm-vs-deception engagement.
 *
 * Connects to the swarm hub's SSE stream (default http://127.0.0.1:18092,
 * the loopback end of the IAP tunnel). Everything here is runtime data from
 * the running lab — nothing is bundled at build time. When no engagement is
 * running the panel says so instead of showing stale numbers.
 */
import { h } from './panels.ts';

interface HubEvent {
  hub_seq: number;
  at: string;
  type: string;
  source?: string;
  agentId?: string;
  role?: string;
  note?: string;
  outcome?: string;
  client?: string;
  path?: string;
  dest?: string;
  reason?: string;
  last?: { type: string; method?: string; path?: string; status?: number; answer?: string | null };
}

interface AgentState {
  agentId: string;
  role: string;
  state?: string;
  outcome?: string;
  toolCalls?: number;
  tokens?: unknown;
  lastType?: string;
  lastAt?: string;
  note?: string;
}

// Use the dashboard's same-origin Vite proxy. This avoids browser cross-origin
// restrictions and keeps the UI on the one dashboard instance bound to IPv4.
const DEFAULT_HUB = '/hub/vm1';
/** Above this many agents the panel shows one coloured cell per agent instead of cards. */
const CARD_LIMIT = 24;

/**
 * The Live tab may only talk to this dashboard's own origin (the /hub proxy)
 * or an explicit loopback hub. Anything else is refused before any request.
 */
export function isAllowedHub(url: string): boolean {
  if (/^\/(?!\/)/.test(url)) return true; // same-origin path, not protocol-relative
  try {
    const u = new URL(url);
    return u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}
const TIMELINE_MAX = 60;

const severity = (e: HubEvent): 'deny' | 'warn' | 'ok' | 'info' => {
  if (e.type.startsWith('defense.revoked') || e.type.startsWith('defense.denied') || e.type === 'defense.egress.allowed' || e.outcome === 'error') return 'deny';
  if (e.type.startsWith('defense.bait') || e.type.startsWith('defense.canary') || e.type === 'defense.egress.denied' || e.type === 'control.rejected') return 'warn';
  if (e.type === 'engagement.started' || e.type === 'control.accepted' || e.outcome === 'success') return 'ok';
  return 'info';
};

const label = (e: HubEvent): string => {
  const who = e.agentId ?? e.client ?? '';
  switch (e.type) {
    case 'engagement.started': return `Engagement started (${e.at.slice(11, 19)})`;
    case 'engagement.completed': return 'Engagement completed';
    case 'agent.started': return `${who} joined as ${e.role}`;
    case 'agent.done': return `${who} finished — ${e.outcome ?? 'unknown'}`;
    case 'agent.state': return `${who} · ${e.last?.type ?? ''}${e.last?.path ? ` ${e.last.method ?? 'GET'} ${e.last.path}` : ''}${e.last?.status ? ` → ${e.last.status}` : ''}`;
    case 'defense.revoked': return `REVOKED ${e.client ?? ''} — ${e.reason ?? ''}`;
    case 'defense.denied': return `Denied ${e.client ?? ''} ${e.path ?? ''}`;
    case 'defense.bait.served': return `Bait served to ${e.client ?? ''} at ${e.path ?? ''}`;
    case 'defense.canary.used': return `Canary credential used by ${e.client ?? ''}`;
    case 'defense.egress.denied': return `Egress DENIED ${e.client ?? ''} → ${e.dest ?? ''}`;
    case 'defense.egress.allowed': return `Egress ALLOWED ${e.client ?? ''} → ${e.dest ?? ''}`;
    case 'control.accepted': return `Trusted alert accepted (${e.client ?? ''})`;
    case 'control.rejected': return `Control event rejected — ${e.reason ?? ''}`;
    default: return `${who ? `${who} · ` : ''}${e.type}`;
  }
};

/** Two side-by-side live panels, one per lab VM, plus a running comparison strip. */
export function initLive(root: HTMLElement): void {
  const grid = h('div', { class: 'live-compare' });
  root.replaceChildren(grid);
  for (const [id, title] of [['vm1', 'VM1'], ['vm2', 'VM2']] as const) {
    const pane = h('div', { class: 'live-pane', 'data-live-lab': id });
    grid.append(pane);
    initLivePanel(pane, `/hub/${id}`, title);
  }
}

export function initLivePanel(root: HTMLElement, defaultHub = DEFAULT_HUB, title = 'Live'): void {
  let source: EventSource | null = null;
  let statePoll: number | null = null;
  let streamConnected = false;
  const events: HubEvent[] = [];
  const seenSequences = new Set<number>();
  const agents = new Map<string, AgentState>();
  let engagement: { status?: string; startedAt?: string | null; id?: string | null } = {};
  let bufferedEvents = 0;

  const statusEl = h('span', { class: 'chip', 'data-live-status': '' }, 'not connected');
  const urlInput = h('input', {
    type: 'text',
    value: defaultHub,
    'aria-label': `${title} swarm hub URL`,
    style: 'width:min(360px, 70vw)',
    class: 'live-url',
  });
  const connectBtn = h('button', { type: 'button', class: 'btn' }, 'Connect');
  const countersEl = h('div', { class: 'chips', 'data-live-counters': '' });
  const agentsEl = h('div', { class: 'live-agents', 'data-live-agents': '' });
  const timelineEl = h('ul', { class: 'live-timeline', 'data-live-timeline': '', role: 'log', 'aria-live': 'polite' });

  root.append(
    h('section', { class: 'exp-head' },
      h('span', { class: 'badge badge-measured' }, `${title} — live engagement`),
      h('p', { class: 'muted small' }, 'Real-time events from an isolated swarm engagement via the swarm hub (SSE). Not production data.'),
      h('div', { class: 'live-controls' }, urlInput, ' ', connectBtn, ' ', statusEl),
    ),
    countersEl,
    h('h3', {}, 'Swarm agents'),
    h('p', { class: 'muted small live-legend' },
      h('span', { class: 'live-cell live-cell-active' }), ' active  ',
      h('span', { class: 'live-cell live-cell-legit' }), ' legit success  ',
      h('span', { class: 'live-cell live-cell-breach' }), ' red exported  ',
      h('span', { class: 'live-cell live-cell-revoked' }), ' revoked  ',
      h('span', { class: 'live-cell live-cell-done' }), ' blocked / no objective / error · live counts are best-effort; the result file is the record'),
    agentsEl,
    h('h3', {}, 'Event timeline'),
    timelineEl,
  );

  const setStatus = (text: string, cls: '' | 'ok' | 'bad' | 'warn') => {
    statusEl.textContent = text;
    statusEl.className = cls ? `chip ${cls}` : 'chip';
  };
  const stopStatePolling = () => {
    if (statePoll !== null) window.clearInterval(statePoll);
    statePoll = null;
  };
  const markLive = () => {
    const watermark = document.getElementById('watermark');
    const badge = document.querySelector<HTMLElement>('.sim-badge');
    if (watermark) { watermark.textContent = 'LIVE LAB · isolated synthetic target · not production'; watermark.classList.add('measured'); }
    if (badge) { badge.textContent = 'LIVE LAB'; badge.title = 'Real-time events from the isolated lab'; }
  };

  const agentCard = (a: AgentState) =>
    h('div', { class: `live-agent ${a.outcome === 'revoked' ? 'live-agent-denied' : ''}` },
      h('div', { class: 'live-agent-head' },
        h('strong', {}, a.agentId),
        h('span', { class: 'chip' }, a.role),
        a.outcome ? h('span', { class: `chip ${a.outcome === 'success' ? 'ok' : a.outcome === 'revoked' ? 'bad' : ''}` }, a.outcome) : null,
      ),
      h('div', { class: 'muted small' },
        `${a.toolCalls ?? 0} tool calls · last ${a.lastType ?? '—'}`,
      ),
    );

  const agentCell = (a: AgentState) => h('span', {
    class: `live-cell ${a.outcome === 'revoked' ? 'live-cell-revoked' : a.outcome === 'success' ? (a.role.startsWith('legit') ? 'live-cell-legit' : 'live-cell-breach') : a.outcome ? 'live-cell-done' : 'live-cell-active'}`,
    title: `${a.agentId} · ${a.role}${a.outcome ? ` · ${a.outcome}` : ''}`,
  });

  // Coalesce bursts (hundreds of events per second at 250 agents) into one paint per frame.
  let renderQueued = false;
  const render = () => {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => { renderQueued = false; paint(); });
  };
  const paint = () => {
    // Counters
    const red = [...agents.values()].filter((a) => !a.role.startsWith('legit'));
    const revoked = red.filter((a) => a.outcome === 'revoked').length;
    const breached = red.filter((a) => a.outcome === 'success').length;
    countersEl.replaceChildren(
      h('span', { class: 'chip' }, `Engagement: ${engagement?.status ?? 'unknown'}`),
      h('span', { class: 'chip' }, `Agents: ${agents.size}`),
      h('span', { class: 'chip' }, `Hub events: ${Math.max(bufferedEvents, events.length)}`),
      h('span', { class: 'chip bad' }, `Red team revoked: ${revoked}/${red.length}`),
      h('span', { class: 'chip warn' }, `Red team exported: ${breached}/${red.length}`),
      h('span', { class: 'chip ok' }, `Legit success: ${[...agents.values()].filter((a) => a.role.startsWith('legit') && a.outcome === 'success').length}`),
    );
    agentsEl.className = agents.size > CARD_LIMIT ? 'live-agents live-agents-dense' : 'live-agents';
    agentsEl.replaceChildren(...(agents.size
      ? [...agents.values()].map(agents.size > CARD_LIMIT ? agentCell : agentCard)
      : [h('p', { class: 'empty' }, 'Waiting for agent updates…')]),
    );
    timelineEl.replaceChildren(
      ...(events.length
        ? events.slice(-TIMELINE_MAX).reverse().map((e) => h('li', { class: `live-event live-${severity(e)}` }, h('span', { class: 'live-event-at' }, e.at.slice(11, 23)), label(e)))
        : [h('li', { class: 'live-event muted' }, 'Waiting for hub events…')]),
    );
  };

  const observe = (e: HubEvent) => {
    if (e.type === 'engagement.started') {
      events.splice(0, events.length);
      seenSequences.clear();
      agents.clear();
      engagement = {};
    }
    if (seenSequences.has(e.hub_seq)) return;
    seenSequences.add(e.hub_seq);
    events.push(e);
    if (events.length > 4 * TIMELINE_MAX) events.splice(0, events.length - 2 * TIMELINE_MAX);
    if (e.agentId && (e.type === 'agent.started' || e.type === 'agent.state' || e.type === 'agent.done')) {
      const prev = agents.get(e.agentId) ?? ({ agentId: e.agentId, role: e.role ?? '?' } as AgentState);
      agents.set(e.agentId, {
        ...prev,
        role: e.role ?? prev.role,
        lastType: e.type === 'agent.state' ? e.last?.type : e.type,
        outcome: e.outcome ?? prev.outcome,
        note: e.note ?? prev.note,
        toolCalls: (prev.toolCalls ?? 0) + (e.type === 'agent.state' && e.last?.type === 'tool.http' ? 1 : 0),
      });
    }
    if (e.type.startsWith('engagement.')) engagement = { ...engagement, status: e.type === 'engagement.started' ? 'running' : 'completed', id: (e as HubEvent & { engagementId?: string }).engagementId ?? engagement.id };
    // Defense-side revocation shows on the agent card too.
    if (e.type === 'defense.revoked' && e.client?.startsWith('peer:')) {
      const id = e.client.slice(5);
      const prev = agents.get(id);
      if (prev) agents.set(id, { ...prev, outcome: 'revoked' });
    }
    render();
  };

  const connect = () => {
    source?.close();
    stopStatePolling();
    streamConnected = false;
    events.splice(0, events.length);
    seenSequences.clear();
    agents.clear();
    const base = urlInput.value.trim().replace(/\/$/, '');
    if (!isAllowedHub(base)) {
      setStatus('refused: hub must be /hub or http://127.0.0.1:<port>', 'bad');
      return;
    }
    const loadState = async () => {
      try {
        const response = await fetch(`${base}/state`, { cache: 'no-store', signal: AbortSignal.timeout(3000) });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const snapshot = await response.json() as { engagement?: typeof engagement; agents?: AgentState[]; events?: number };
        engagement = snapshot.engagement ?? {};
        bufferedEvents = Number(snapshot.events) || 0;
        if (!streamConnected) agents.clear();
        for (const a of snapshot.agents ?? []) agents.set(a.agentId, a);
        if (engagement.status === 'running' || engagement.status === 'completed') {
          markLive();
          if (!streamConnected) setStatus(`connected · ${engagement.status} · polling state`, 'warn');
        } else if (!streamConnected) {
          setStatus('connected · no active engagement', 'ok');
        }
        render();
      } catch {
        if (!streamConnected) setStatus(`hub unavailable at ${base}`, 'bad');
      }
    };
    setStatus('connecting…', 'warn');
    void loadState();
    source = new EventSource(`${base}/stream`);
    source.addEventListener('lab', (ev) => {
      streamConnected = true;
      markLive();
      setStatus('live event stream', 'ok');
      try { observe(JSON.parse((ev as MessageEvent).data) as HubEvent); } catch { /* ignore malformed */ }
    });
    source.onopen = () => {
      streamConnected = true;
      stopStatePolling();
      setStatus('event stream connected', 'ok');
      void loadState();
    };
    source.onerror = () => {
      streamConnected = false;
      setStatus('event stream reconnecting · polling agent state', 'warn');
      void loadState();
      if (statePoll === null) statePoll = window.setInterval(() => { void loadState(); }, 1500);
      // A failed first connect (tunnel not up yet, proxy 502) closes an EventSource for
      // good; the browser will not retry it. Reopen it ourselves so the timeline fills
      // once the hub is reachable. The hub replays its ring buffer on reconnect.
      const failed = source;
      if (failed?.readyState === EventSource.CLOSED) {
        window.setTimeout(() => { if (source === failed) connect(); }, 3000);
      }
    };
  };

  connectBtn.addEventListener('click', connect);
  connect();
}
