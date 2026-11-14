// Container entry: runs the deterministic scripted agent through the same
// harness + guard used on the host, against the honeypot only. Then attempts
// three things that must fail, and prints a JSON verdict for the validator.
import { runAgent, ChainLog } from './harness.mjs';
import { scriptedProvider } from './agent-scripted.mjs';

const ORIGIN = 'http://honeypot:8080';
const log = new ChainLog();
await new Promise((r) => setTimeout(r, 1500));
const result = await runAgent({
  provider: scriptedProvider,
  origin: ORIGIN,
  guardOpts: { allowContainerHosts: ['honeypot'] },
  budget: { maxToolCalls: 30, maxWallMs: 30000 },
  log,
});

const probe = async (url) => {
  try {
    await fetch(url, { signal: AbortSignal.timeout(3000), redirect: 'manual' });
    return 'REACHED';
  } catch (err) {
    return `blocked (${String(err?.cause?.code ?? err?.name ?? 'error')})`;
  }
};

console.log(
  JSON.stringify({
    driver: 'verdict',
    agent: { stopReason: result.stopReason, toolCalls: result.toolCalls, answer: result.answer, tokens: result.tokens, logHead: log.head },
    egress: {
      'http://203.0.113.45/': await probe('http://203.0.113.45/'),
      'https://example.com/': await probe('https://example.com/'),
      'http://1.1.1.1/': await probe('http://1.1.1.1/'),
    },
    guard: {
      absoluteUrl: (await import('./guard.mjs')).createGuard(ORIGIN, { allowContainerHosts: ['honeypot'] }).check('GET', 'http://203.0.113.45/').ok ? 'ALLOWED' : 'refused',
    },
  }),
);
