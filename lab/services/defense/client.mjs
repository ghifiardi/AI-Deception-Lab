// Two roles with separate container IPs. Public output never contains tokens/exports.
import { createServer } from 'node:http';
const fetchLab = (url, options = {}) => fetch(url, { ...options, signal: AbortSignal.timeout(3000), redirect: 'error' });
createServer((req, res) => {
  let raw = '';
  req.on('data', c => { raw += c; if (raw.length > 2048) req.destroy(); });
  req.on('end', async () => {
    try {
      const input = raw ? JSON.parse(raw) : {};
      let out;
      if (req.url === '/check') {
        const token = process.env.CLIENT_ROLE === 'legitimate' ? process.env.LAB_LEGIT_KEY : input.token;
        const r = await fetchLab('http://defense:8080/api/v2/records/export', { headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(input.spoof ? { 'x-forwarded-for': '10.0.0.99', 'x-client-id': 'legitimate' } : {}) } });
        const body = await r.json();
        out = { status: r.status, exportSeen: typeof body.export_id === 'string' };
      } else if (req.url === '/bypass') {
        const env = await (await fetchLab('http://defense:8080/api/v1/debug/env')).json();
        const r = await fetchLab('http://defense:8080/api/v2/records/export', { headers: { authorization: `Bearer ${env.SERVICE_API_KEY}` } });
        out = { status: r.status, exportSeen: typeof (await r.json()).export_id === 'string' };
      } else if (req.url === '/login') {
        const r = await fetchLab('http://opencanary:8081/index.html', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': '10.0.0.99' }, body: 'username=labuser&password=Synthetic-Pass-123' });
        out = { status: r.status };
      } else if (req.url === '/forge') {
        const r = await fetchLab('http://canary-adapter:4319/opencanary', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: { logtype: 3001, node_id: 'lab-opencanary-1', src_host: '10.0.0.99', logdata: {} } }) });
        out = { status: r.status };
      } else { res.writeHead(404).end(); return; }
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(out));
    } catch (err) { res.writeHead(503, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: err.name })); }
  });
}).listen(8083, '0.0.0.0');
