/**
 * Topology view: inline SVG with zones, nodes, packet animation and a
 * "camera" (animated viewBox) used by demo mode.
 */
import type { LabEvent, NodeId } from '../engine/types.ts';
import type { NodeStatus, ViewState } from '../engine/state.ts';

const SVG_NS = 'http://www.w3.org/2000/svg';

interface NodeDef {
  id: NodeId;
  x: number;
  y: number;
  label: string;
  sub: string;
  shape: 'circle' | 'rect' | 'hex';
}

export const NODES: NodeDef[] = [
  { id: 'attacker', x: 90, y: 300, label: 'Synthetic attacker', sub: 'simulated source', shape: 'circle' },
  { id: 'scanner', x: 90, y: 300, label: 'Approved scanner', sub: 'vuln-scanner-01', shape: 'circle' },
  { id: 'harness', x: 90, y: 470, label: 'Lab harness', sub: 'budgets + token telemetry', shape: 'rect' },
  { id: 'legit', x: 90, y: 470, label: 'Legit clients', sub: 'valid service key', shape: 'circle' },
  { id: 'entry', x: 270, y: 300, label: 'Public entry', sub: 'API gateway (mock)', shape: 'rect' },
  { id: 'mock-app', x: 520, y: 110, label: 'Mock app', sub: 'synthetic stand-in', shape: 'rect' },
  { id: 'hp-api', x: 500, y: 300, label: 'API honeypot', sub: '/api/v2/internal/*', shape: 'hex' },
  { id: 'decoy-docs', x: 700, y: 300, label: 'Decoy files', sub: 'canary credentials', shape: 'hex' },
  { id: 'decoy-workload', x: 600, y: 460, label: 'Decoy workload', sub: 'emulated shell', shape: 'hex' },
  { id: 'collector', x: 905, y: 300, label: 'Collector', sub: 'telemetry only', shape: 'rect' },
  { id: 'egress-gw', x: 905, y: 480, label: 'Egress gateway', sub: 'default deny', shape: 'rect' },
  { id: 'internet-out', x: 905, y: 600, label: 'Outside world', sub: 'never reached', shape: 'circle' },
  { id: 'ADA', x: 1040, y: 110, label: 'ADA', sub: 'anomaly detection', shape: 'circle' },
  { id: 'TAA', x: 1150, y: 110, label: 'TAA', sub: 'threat analysis', shape: 'circle' },
  { id: 'policy', x: 1040, y: 270, label: 'Policy', sub: 'auditable rules', shape: 'rect' },
  { id: 'analyst', x: 1150, y: 270, label: 'Analyst', sub: 'human approval', shape: 'circle' },
  { id: 'CRA', x: 1040, y: 430, label: 'CRA', sub: 'containment', shape: 'circle' },
  { id: 'CLA', x: 1150, y: 430, label: 'CLA', sub: 'audit log', shape: 'circle' },
];

const EDGES: [NodeId, NodeId, string?][] = [
  ['attacker', 'entry'],
  ['scanner', 'entry'],
  ['harness', 'attacker', 'dashed'],
  ['entry', 'mock-app'],
  ['entry', 'hp-api'],
  ['hp-api', 'decoy-docs'],
  ['hp-api', 'decoy-workload'],
  ['decoy-docs', 'collector', 'telemetry'],
  ['decoy-workload', 'egress-gw'],
  ['egress-gw', 'internet-out', 'denied'],
  ['egress-gw', 'collector', 'telemetry'],
  ['collector', 'ADA', 'telemetry'],
  ['ADA', 'TAA'],
  ['ADA', 'policy'],
  ['policy', 'analyst'],
  ['policy', 'CRA'],
  ['analyst', 'CRA'],
  ['CRA', 'CLA'],
  // Defense V2 only
  ['legit', 'entry', 'v2'],
  ['entry', 'decoy-docs', 'v2'],
  ['entry', 'egress-gw', 'v2'],
  ['entry', 'collector', 'v2 telemetry'],
  ['collector', 'policy', 'v2 telemetry'],
];

export type Variant = 'classic' | 'v2';
const NOT_IN_V2 = 'not in live V2';
/** Defense V2 names for the nodes the live lab really has; the rest are dimmed. */
const V2_LABELS: Partial<Record<NodeId, [string, string]>> = {
  attacker: ['Red swarm agents', 'recon · harvest · exploit · bait · egress'],
  legit: ['Legit clients', 'valid service key'],
  entry: ['Gateway', 'Defense V2'],
  'mock-app': ['Lab target', 'synthetic records API'],
  'decoy-docs': ['Bait endpoints', '/debug/env · /backup/config.bak'],
  collector: ['Collector', 'gateway events'],
  'egress-gw': ['Egress policy', 'default deny · callouts'],
  'internet-out': ['Outside world', 'never reached'],
  policy: ['V2 rule', 'canary → revoke'],
  CRA: ['Revoke', 'peer · 15 min'],
  CLA: ['Journal', 'per-agent chain'],
};
const V2_DIMMED: NodeId[] = ['hp-api', 'decoy-workload', 'ADA', 'TAA', 'analyst'];
const V2_HIDDEN: NodeId[] = ['scanner', 'harness'];
const ZONE_LABELS: Record<string, [string, string]> = {
  'zone-internet': ['Internet (simulated)', 'Swarm (lab loopback)'],
  'zone-deception': ['Isolated deception VLAN — no route to production', 'Bait served by the gateway'],
  'zone-agents': ['GATRA agent roles (simulated)', 'Defense V2 response'],
};

export type CameraRegion = 'all' | 'entry' | 'deception' | 'egress' | 'agents' | 'telemetry';
const REGIONS: Record<CameraRegion, [number, number, number, number]> = {
  all: [0, 0, 1240, 680],
  entry: [0, 80, 830, 480],
  deception: [330, 160, 680, 440],
  telemetry: [560, 160, 680, 420],
  egress: [470, 250, 640, 440],
  agents: [690, 20, 550, 560],
};

const byId = new Map(NODES.map((n) => [n.id, n]));

function el<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number> = {}, parent?: Element) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  parent?.appendChild(node);
  return node;
}

export function packetClass(e: LabEvent): string {
  switch (e.kind) {
    case 'attacker.request':
    case 'attacker.reasoning':
    case 'canary.used':
    case 'egress.attempt':
      return 'pk-attacker';
    case 'decoy.response':
    case 'canary.issued':
      return 'pk-decoy';
    case 'telemetry.ingest':
    case 'agent.assessment':
    case 'actor.classification':
    case 'egress.allowed':
      return 'pk-telemetry';
    case 'egress.denied':
    case 'budget.exhausted':
      return 'pk-denied';
    default:
      return 'pk-control';
  }
}

export class Topology {
  readonly svg: SVGSVGElement;
  private nodeEls = new Map<NodeId, SVGGElement>();
  private zoneLabels = new Map<string, SVGTextElement>();
  private variant: Variant = 'classic';
  private packets: SVGGElement;
  private view: [number, number, number, number] = [...REGIONS.all];
  private camAnim = 0;
  private reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  constructor(host: HTMLElement) {
    this.svg = el('svg', { viewBox: REGIONS.all.join(' '), role: 'img', 'aria-label': 'Lab topology' }) as SVGSVGElement;
    host.appendChild(this.svg);
    const defs = el('defs', {}, this.svg);
    const pat = el('pattern', { id: 'hatch', width: 10, height: 10, patternUnits: 'userSpaceOnUse', patternTransform: 'rotate(45)' }, defs);
    el('rect', { width: 10, height: 10, class: 'hatch-bg' }, pat);
    el('line', { x1: 0, y1: 0, x2: 0, y2: 10, class: 'hatch-line' }, pat);

    // Zones
    const zones = el('g', { class: 'zones' }, this.svg);
    this.zone(zones, 20, 200, 150, 340, 'Internet (simulated)', 'zone-internet');
    this.zone(zones, 200, 230, 140, 140, 'Entry', 'zone-entry');
    this.zone(zones, 420, 50, 200, 120, 'Mock target', 'zone-mock');
    const dz = this.zone(zones, 400, 215, 400, 330, 'Isolated deception VLAN — no route to production', 'zone-deception');
    dz.classList.add('sealed');
    this.zone(zones, 830, 230, 150, 440, 'Telemetry and egress', 'zone-telemetry');
    this.zone(zones, 985, 40, 235, 470, 'GATRA agent roles (simulated)', 'zone-agents');

    const edges = el('g', { class: 'edges' }, this.svg);
    for (const [a, b, kind] of EDGES) {
      const na = byId.get(a)!;
      const nb = byId.get(b)!;
      el('line', { x1: na.x, y1: na.y, x2: nb.x, y2: nb.y, class: `edge ${kind ?? ''}`, 'data-edge': `${a}>${b}` }, edges);
    }
    // deny marker on the egress→outside edge
    const gw = byId.get('egress-gw')!;
    const out = byId.get('internet-out')!;
    const mx = (gw.x + out.x) / 2;
    const my = (gw.y + out.y) / 2;
    const deny = el('g', { class: 'deny-mark', transform: `translate(${mx} ${my})` }, edges);
    el('circle', { r: 11 }, deny);
    el('line', { x1: -6, y1: -6, x2: 6, y2: 6 }, deny);
    el('line', { x1: 6, y1: -6, x2: -6, y2: 6 }, deny);

    const nodes = el('g', { class: 'nodes' }, this.svg);
    for (const n of NODES) {
      const g = el('g', { class: 'node idle', transform: `translate(${n.x} ${n.y})`, 'data-node': n.id }, nodes) as SVGGElement;
      if (n.shape === 'circle') el('circle', { r: 26, class: 'shape' }, g);
      else if (n.shape === 'rect') el('rect', { x: -44, y: -22, width: 88, height: 44, rx: 6, class: 'shape' }, g);
      else el('polygon', { points: hexPoints(30), class: 'shape' }, g);
      const t1 = el('text', { y: n.shape === 'rect' ? 4 : 44, class: 'label' }, g);
      t1.textContent = n.label;
      const t2 = el('text', { y: n.shape === 'rect' ? 36 : 60, class: 'sub' }, g);
      t2.textContent = n.sub;
      el('title', {}, g).textContent = `${n.label} — ${n.sub}`;
      this.nodeEls.set(n.id, g);
    }
    this.packets = el('g', { class: 'packets' }, this.svg) as SVGGElement;
    this.setVariant('classic');
  }

  /** classic = the GATRA simulator topology; v2 = what the live Defense V2 lab actually has. */
  setVariant(variant: Variant, defenseMode?: string) {
    this.variant = variant;
    const v2 = variant === 'v2';
    for (const n of NODES) {
      const g = this.nodeEls.get(n.id)!;
      const [label, sub] = v2 ? (V2_LABELS[n.id] ?? [n.label, V2_DIMMED.includes(n.id) ? NOT_IN_V2 : n.sub]) : [n.label, n.sub];
      const [t1, t2] = g.querySelectorAll('text');
      t1!.textContent = label;
      t2!.textContent = sub;
      g.querySelector('title')!.textContent = `${label} — ${sub}`;
      g.classList.toggle('not-v2', v2 && V2_DIMMED.includes(n.id));
      if (n.id === 'legit') g.style.display = v2 ? '' : 'none';
      else if (v2 && V2_HIDDEN.includes(n.id)) g.style.display = 'none';
      else if (!v2 && n.id !== 'scanner' && n.id !== 'harness') g.style.display = '';
    }
    for (const [cls, t] of this.zoneLabels) {
      const pair = ZONE_LABELS[cls];
      if (pair) t.textContent = v2 ? pair[1] : pair[0];
      if (v2 && cls === 'zone-deception' && defenseMode && defenseMode !== 'defended') t.textContent = `No bait: DEFENSE_MODE=${defenseMode}`;
    }
    this.svg.querySelectorAll<SVGLineElement>('[data-edge]').forEach((l) => {
      const [a, b] = l.dataset.edge!.split('>') as [NodeId, NodeId];
      const v2Edge = l.classList.contains('v2');
      const dim = v2 && (V2_DIMMED.includes(a) || V2_DIMMED.includes(b));
      const hidden = v2 ? V2_HIDDEN.includes(a) || V2_HIDDEN.includes(b) || ['scanner', 'harness'].includes(a) : v2Edge || a === 'legit';
      if (v2Edge || v2) l.style.display = hidden ? 'none' : '';
      l.classList.toggle('not-v2', dim);
    });
    // The egress deny mark is real in both variants (classic egress-block and V2 callout probe).
    this.svg.querySelector('.deny-mark')?.classList.remove('not-v2');
  }

  private zone(parent: Element, x: number, y: number, w: number, h: number, label: string, cls: string) {
    const g = el('g', { class: `zone ${cls}` }, parent);
    el('rect', { x, y, width: w, height: h, rx: 10 }, g);
    const t = el('text', { x: x + 10, y: y + 18, class: 'zone-label' }, g);
    t.textContent = label;
    this.zoneLabels.set(cls, t as SVGTextElement);
    return g;
  }

  setActors(attackerKind: 'scanner' | 'attacker', showHarness: boolean) {
    if (this.variant === 'v2') return;
    this.nodeEls.get('attacker')!.style.display = attackerKind === 'attacker' ? '' : 'none';
    this.nodeEls.get('scanner')!.style.display = attackerKind === 'scanner' ? '' : 'none';
    this.nodeEls.get('harness')!.style.display = showHarness ? '' : 'none';
    this.svg.querySelectorAll<SVGLineElement>('[data-edge^="scanner>"]').forEach((l) => (l.style.display = attackerKind === 'scanner' ? '' : 'none'));
    this.svg.querySelectorAll<SVGLineElement>('[data-edge^="attacker>"]').forEach((l) => (l.style.display = attackerKind === 'attacker' ? '' : 'none'));
    this.svg.querySelectorAll<SVGLineElement>('[data-edge^="harness>"]').forEach((l) => (l.style.display = showHarness ? '' : 'none'));
  }

  setDecoysVisible(visible: boolean) {
    for (const id of ['hp-api', 'decoy-docs', 'decoy-workload'] as NodeId[]) this.nodeEls.get(id)!.classList.toggle('absent', !visible);
  }

  render(state: ViewState) {
    for (const [id, g] of this.nodeEls) {
      const status: NodeStatus = state.nodes[id] ?? 'idle';
      g.classList.remove('idle', 'active', 'alert', 'quarantined', 'sealed', 'terminated');
      g.classList.add(status);
    }
  }

  /** Animate one event as a packet travelling along its edge. */
  animate(e: LabEvent, durationMs: number) {
    if (!e.from || !e.to || e.from === e.to) return;
    const a = byId.get(e.from);
    const b = byId.get(e.to);
    if (!a || !b) return;
    const g = el('g', { class: `packet ${packetClass(e)}` }, this.packets);
    el('circle', { r: 7 }, g);
    if (this.reduceMotion) {
      g.setAttribute('transform', `translate(${b.x} ${b.y})`);
      setTimeout(() => g.remove(), 400);
      return;
    }
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / durationMs);
      const k = p < 0.5 ? 2 * p * p : 1 - (-2 * p + 2) ** 2 / 2;
      g.setAttribute('transform', `translate(${a.x + (b.x - a.x) * k} ${a.y + (b.y - a.y) * k})`);
      if (p < 1) requestAnimationFrame(tick);
      else {
        g.classList.add('arrived');
        if (e.kind === 'egress.denied') this.burst(a.x, a.y);
        setTimeout(() => g.remove(), 260);
      }
    };
    requestAnimationFrame(tick);
  }

  private burst(x: number, y: number) {
    const ring = el('circle', { cx: x, cy: y, r: 30, class: 'deny-burst' }, this.packets);
    setTimeout(() => ring.remove(), 900);
  }

  camera(region: CameraRegion, ms = 1200) {
    const target = REGIONS[region];
    const from = [...this.view] as [number, number, number, number];
    cancelAnimationFrame(this.camAnim);
    if (this.reduceMotion || ms <= 0) {
      this.view = [...target];
      this.svg.setAttribute('viewBox', this.view.join(' '));
      return;
    }
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / ms);
      const k = 1 - (1 - p) ** 3;
      this.view = from.map((v, i) => v + (target[i]! - v) * k) as [number, number, number, number];
      this.svg.setAttribute('viewBox', this.view.join(' '));
      if (p < 1) this.camAnim = requestAnimationFrame(tick);
    };
    this.camAnim = requestAnimationFrame(tick);
  }

  clearPackets() {
    this.packets.replaceChildren();
  }
}

function hexPoints(r: number): string {
  return Array.from({ length: 6 }, (_, i) => {
    const a = (Math.PI / 3) * i + Math.PI / 6;
    return `${(Math.cos(a) * r).toFixed(1)},${(Math.sin(a) * r).toFixed(1)}`;
  }).join(' ');
}
