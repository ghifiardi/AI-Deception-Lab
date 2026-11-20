/**
 * OpenAI-compatible adapter for the user's hosted inference endpoint.
 * The only permitted remote host is openai.ina17.com; the API key is read from
 * the local process environment and is never included in run artifacts.
 */
const BASE_URL = 'https://openai2.ina17.com/v1';
const ALLOWED_HOSTS = new Set(['openai.ina17.com', 'openai2.ina17.com']);

function endpoint(baseUrl) {
  let url;
  try { url = new URL(baseUrl); } catch { throw new Error('Hosted model endpoint URL is invalid.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.port && url.port !== '443') || !ALLOWED_HOSTS.has(url.hostname.toLowerCase())) {
    throw new Error('Hosted model endpoint must use the approved HTTPS model host.');
  }
  return { baseUrl: baseUrl.replace(/\/+$/, ''), allowedHost: { host: url.hostname.toLowerCase(), port: 443 } };
}

// Transient failures worth retrying: the connection dropped or the upstream was
// briefly unavailable. Observed 2026-11-15: four agents of one engagement failed
// together with "TypeError: fetch failed" while the rest continued, i.e. an
// upstream reset of in-flight requests, not a budget or prompt-size limit.
const TRANSIENT_CODES = new Set(['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'EAI_AGAIN', 'UND_ERR_SOCKET', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'UND_ERR_CLOSED']);
const TRANSIENT_STATUS = new Set([429, 500, 502, 503, 504]);
export const DEFAULT_RETRY_DELAYS_MS = [2000, 8000];

/** "fetch failed" hides the real reason in err.cause; surface it. */
export function describeFetchError(err) {
  const c = err?.cause;
  const base = `${err?.name ?? 'Error'}: ${err?.message ?? String(err)}`;
  return c ? `${base} (cause: ${c.code ?? c.name ?? 'unknown'}${c.message ? `: ${c.message}` : ''})` : base;
}

/** Retry only network-level failures; never the lab egress guard or our own timeout. */
export function isTransientFetchError(err) {
  if (err?.name === 'TimeoutError' || err?.name === 'AbortError') return false;
  const code = err?.cause?.code ?? err?.code;
  if (code === 'ELAB_EGRESS_BLOCKED') return false;
  return err instanceof TypeError && (code === undefined || TRANSIENT_CODES.has(code));
}

class HttpStatusError extends Error {
  constructor(status, retryAfterMs) {
    super(`hosted model endpoint returned HTTP ${status}`);
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

export function openAICompatibleAllowedHost(baseUrl = BASE_URL) { return endpoint(baseUrl).allowedHost; }

export function createOpenAICompatibleAdapter({ model, baseUrl = BASE_URL, apiKey = process.env.INA17_API_KEY ?? process.env.OPENAI_API_KEY, authHeader = 'authorization', fetchImpl = fetch, timeoutMs = 600000, retryDelaysMs = DEFAULT_RETRY_DELAYS_MS, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  if (!apiKey || apiKey.trim().length < 8) throw new Error('Set INA17_API_KEY (or OPENAI_API_KEY) in the local dashboard terminal before starting it.');
  if (!model || !/^[\w./:-]{1,120}$/.test(model)) throw new Error('Enter the exact model ID provided by the hosted endpoint.');
  const endpointConfig = endpoint(baseUrl);
  if (!['authorization', 'x-bf-vk'].includes(authHeader)) throw new Error('Hosted model authentication header is not allowed.');
  const messages = [];
  return {
    kind: 'openai-compatible',
    name: `openai-compatible:${model}`,
    model,
    measuresTokens: true,
    describe: () => ({
      provider: 'OpenAI-compatible remote endpoint',
      endpoint: endpointConfig.baseUrl,
      model,
      inference: { temperature: 0.2, streaming: false },
      tokenSource: 'chat completion usage.prompt_tokens / usage.completion_tokens',
    }),
    start(task, tools) {
      messages.splice(0, messages.length, { role: 'user', content: task });
      return {
        messages,
        tools: tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.schema } })),
      };
    },
    async step(conv) {
      // The request has no side effects on the lab target, so a bounded retry is
      // safe. A failed attempt may still have consumed upstream tokens that the
      // endpoint never reported; retries are recorded in the turn metadata.
      const failures = [];
      let data;
      for (let attempt = 0; ; attempt++) {
        try {
          const response = await fetchImpl(`${endpointConfig.baseUrl}/chat/completions`, {
            method: 'POST',
            headers: { [authHeader]: authHeader === 'x-bf-vk' ? apiKey : `Bearer ${apiKey}`, 'content-type': 'application/json' },
            body: JSON.stringify({ model, messages: conv.messages, tools: conv.tools, tool_choice: 'auto', temperature: 0.2, stream: false }),
            redirect: 'error',
            signal: AbortSignal.timeout(timeoutMs),
          });
          if (!response.ok) {
            const ra = Number(response.headers?.get?.('retry-after'));
            throw new HttpStatusError(response.status, Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, 30000) : null);
          }
          data = await response.json();
          break;
        } catch (err) {
          const transient = err instanceof HttpStatusError ? TRANSIENT_STATUS.has(err.status) : isTransientFetchError(err);
          const detail = err instanceof HttpStatusError ? err.message : describeFetchError(err);
          failures.push(detail);
          if (!transient || attempt >= retryDelaysMs.length) {
            const final = new Error(failures.length > 1 ? `hosted model request failed after ${failures.length} attempts: ${failures.join(' | ')}` : detail);
            final.name = err instanceof HttpStatusError ? 'HostedModelHttpError' : 'HostedModelFetchError';
            throw final;
          }
          await sleep(err.retryAfterMs ?? retryDelaysMs[attempt]);
        }
      }
      const choice = data.choices?.[0];
      if (!choice?.message) throw new Error('hosted model returned no chat completion choice');
      const message = choice.message;
      const toolCalls = (message.tool_calls ?? []).map((tc, i) => ({ ...tc, id: tc.id ?? `remote_call_${i}` }));
      const assistant = { role: 'assistant', content: message.content ?? null };
      if (toolCalls.length) assistant.tool_calls = toolCalls;
      conv.messages.push(assistant);
      const usage = data.usage;
      return {
        model: data.model ?? model,
        stopReason: choice.finish_reason ?? null,
        durationMs: null,
        meta: failures.length ? { retries: failures.length, retryCauses: failures.map((f) => f.slice(0, 160)) } : null,
        usage: Number.isFinite(usage?.prompt_tokens) && Number.isFinite(usage?.completion_tokens)
          ? { input: usage.prompt_tokens, output: usage.completion_tokens, cacheRead: 0, cacheWrite: 0 }
          : null,
        text: typeof message.content === 'string' ? message.content : '',
        toolCalls: toolCalls.map((tc) => {
          const raw = tc.function?.arguments ?? {};
          let input = raw;
          if (typeof raw === 'string') { try { input = JSON.parse(raw); } catch { input = {}; } }
          return { id: tc.id, name: tc.function?.name ?? '', input };
        }),
      };
    },
    addResults(conv, _turn, results) {
      for (const r of results) conv.messages.push({ role: 'tool', tool_call_id: r.call.id, content: r.content });
    },
    nudge(conv, text) { conv.messages.push({ role: 'user', content: text }); },
  };
}
