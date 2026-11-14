/**
 * In-process egress guard for the experiment runner.
 *
 * Patches net.Socket.prototype.connect, which every outbound TCP connection in
 * Node goes through (http, https/tls, fetch/undici). Connections to hosts not
 * on the allow list are refused before any packet is sent and recorded.
 *
 *   loopback (127.0.0.0/8, ::1, localhost)  always allowed (lab target, local model runtime)
 *   extra hosts                             only those named by the runner (e.g. the Claude API host)
 *
 * Limits: this governs THIS process only. It cannot restrict other processes
 * such as the Ollama daemon; see docs/DESIGN.md (TB7) for how that is handled.
 */
import net from 'node:net';

const LOOPBACK = (host) =>
  host === 'localhost' || host === '::1' || host === '[::1]' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) || host === '::ffff:127.0.0.1';

let installed = null;

/** Extract host/port from the many net connect() call shapes. */
function target(args) {
  const [a, b] = args;
  if (Array.isArray(a)) return target(a);
  if (a && typeof a === 'object') {
    if (a.path) return { host: 'unix-socket', port: 0, unix: true };
    return { host: String(a.host ?? 'localhost'), port: Number(a.port) };
  }
  if (typeof a === 'string' && Number.isNaN(Number(a))) return { host: 'unix-socket', port: 0, unix: true };
  return { host: typeof b === 'string' ? b : 'localhost', port: Number(a) };
}

/**
 * @param {{ allowHosts?: Array<{ host: string, port: number }> }} [opts]
 * @returns {{ policy: object, blocked: Array<{ host: string, port: number }>, allowed: Array<{ host: string, port: number }>, uninstall: () => void }}
 */
export function installEgressGuard(opts = {}) {
  if (installed) installed.uninstall();
  const allowHosts = (opts.allowHosts ?? []).map((h) => ({ host: h.host.toLowerCase(), port: h.port }));
  const blocked = [];
  const allowed = [];
  const original = net.Socket.prototype.connect;

  net.Socket.prototype.connect = function guardedConnect(...args) {
    const t = target(args);
    const host = t.host.toLowerCase().replace(/^\[(.*)\]$/, '$1');
    const ok = t.unix || LOOPBACK(host) || allowHosts.some((a) => a.host === host && a.port === t.port);
    if (!ok) {
      blocked.push({ host, port: t.port });
      const err = Object.assign(new Error(`egress blocked by lab guard: ${host}:${t.port}`), { code: 'ELAB_EGRESS_BLOCKED' });
      process.nextTick(() => this.destroy(err));
      return this;
    }
    if (!LOOPBACK(host) && !t.unix) allowed.push({ host, port: t.port });
    return original.apply(this, args);
  };

  installed = {
    policy: { default: 'deny', loopback: 'allow', allowHosts },
    blocked,
    allowed,
    uninstall() {
      net.Socket.prototype.connect = original;
      installed = null;
    },
  };
  return installed;
}
