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

// Default: the hub proxied through this dashboard's own origin (see
// vite.config.ts server.proxy), so no cross-origin access is ever needed.
const DEFAULT_HUB = '/hub';

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
  if (e.type.startsWith('defense.revoked') || e.type.startsWith('defense.denied') || e.outcome === 'error') return 'deny';
  if (e.type.startsWith('defense.bait') || e.type.startsWith('defense.canary') || e.type === 'control.rejected') return 'warn';
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
    case 'control.accepted': return `Trusted alert accepted (${e.client ?? ''})`;
    case 'control.rejected': return `Control event rejected — ${e.reason ?? ''}`;
    default: return `${who ? `${who} · ` : ''}${e.type}`;
  }
};

export function initLive(root: HTMLElement): void {
  let source: EventSource | null = null;
  const events: HubEvent[] = [];
  const agents = new Map<string, AgentState>();
  let engagement: { status?: string; startedAt?: string | null; id?: string | null } = {};

  const statusEl = h('span', { class: 'chip', 'data-live-status': '' }, 'not connected');
  const urlInput = h('input', {
    type: 'text',
    value: DEFAULT_HUB,
    'aria-label': 'Swarm hub URL',
    style: 'width:220px',
    class: 'live-url',
  });
  const connectBtn = h('button', { type: 'button', class: 'btn' }, 'Connect');
  const countersEl = h('div', { class: 'chips', 'data-live-counters': '' });
  const agentsEl = h('div', { class: 'live-agents', 'data-live-agents': '' });
  const timelineEl = h('ul', { class: 'live-timeline', 'data-live-timeline': '', role: 'log', 'aria-live': 'polite' });

  root.append(
    h('section', { class: 'exp-head' },
      h('span', { class: 'badge badge-measured' }, 'Live — engagement'),
      h('p', { class: 'muted small' }, 'Real-time events from an isolated swarm engagement via the swarm hub (SSE). Not production data.'),
      h('div', { class: 'live-controls' }, urlInput, ' ', connectBtn, ' ', statusEl),
    ),
    countersEl,
    h('h3', {}, 'Swarm agents'),
    agentsEl,
    h('h3', {}, 'Event timeline'),
    timelineEl,
  );

  const setStatus = (text: string, cls: '' | 'ok' | 'bad' | 'warn') => {
    statusEl.textContent = text;
    statusEl.className = cls ? `chip ${cls}` : 'chip';
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

  const render = () => {
    // Counters
    const red = [...agents.values()].filter((a) => !a.role.startsWith('legit'));
    const revoked = red.filter((a) => a.outcome === 'revoked').length;
    countersEl.replaceChildren(
      h('span', { class: 'chip' }, `Engagement: ${engagement?.status ?? 'unknown'}`),
      h('span', { class: 'chip' }, `Agents: ${agents.size}`),
      h('span', { class: 'chip bad' }, `Red team revoked: ${revoked}/${red.length}`),
      h('span', { class: 'chip ok' }, `Legit success: ${[...agents.values()].filter((a) => a.role.startsWith('legit') && a.outcome === 'success').length}`),
    );
    agentsEl.replaceChildren(...[...agents.values()].map(agentCard));
    timelineEl.replaceChildren(
      ...events.slice(-TIMELINE_MAX).reverse().map((e) => h('li', { class: `live-event live-${severity(e)}` }, h('span', { class: 'live-event-at' }, e.at.slice(11, 23)), label(e))),
    );
  };

  const observe = (e: HubEvent) => {
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
    const base = urlInput.value.trim().replace(/\/$/, '');
    if (!isAllowedHub(base)) {
      setStatus('refused: hub must be /hub or http://127.0.0.1:<port>', 'bad');
      return;
    }
    let alive = false;
    setStatus('connecting…', 'warn');
    fetch(`${base}/state`, { signal: AbortSignal.timeout(3000) })
      .then((r) => r.json())
      .then((state: { engagement?: typeof engagement; agents?: AgentState[] }) => {
        engagement = state.engagement ?? {};
        for (const a of state.agents ?? []) agents.set(a.agentId, a);
        render();
      })
      .catch(() => {});
    source = new EventSource(`${base}/stream`);
    source.addEventListener('lab', (ev) => {
      alive = true;
      setStatus('live', 'ok');
      try { observe(JSON.parse((ev as MessageEvent).data) as HubEvent); } catch { /* ignore malformed */ }
    });
    source.onerror = () => {
      if (alive) {
        setStatus('reconnecting…', 'warn');
      } else {
        // Never reached a hub: stop the browser's automatic retries. Connect retries.
        source?.close();
        setStatus(`no engagement at ${base}`, 'bad');
      }
    };
    source.onopen = () => setStatus('live', 'ok');
  };

  connectBtn.addEventListener('click', connect);
  connect();
}
