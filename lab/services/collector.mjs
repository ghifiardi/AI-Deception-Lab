// In-lab telemetry collector: accepts JSON events and writes them to stdout.
// It makes no outbound connections and stores nothing on disk.
import { createServer } from 'node:http';

const MAX_BODY = 8192;
let seq = 0;

createServer((req, res) => {
  if (req.method !== 'POST' || req.url !== '/v1/events') {
    res.writeHead(404).end();
    return;
  }
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (c) => {
    body += c;
    if (body.length > MAX_BODY) req.destroy();
  });
  req.on('end', () => {
    try {
      const event = JSON.parse(body);
      console.log(JSON.stringify({ collector_seq: ++seq, event }));
      res.writeHead(202).end();
    } catch {
      res.writeHead(400).end();
    }
  });
}).listen(4318, () => console.log(JSON.stringify({ collector: 'listening', port: 4318 })));
