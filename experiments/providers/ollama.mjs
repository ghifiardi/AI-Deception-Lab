/**
 * Local model adapter for an Ollama-compatible runtime (default http://127.0.0.1:11434).
 *
 * No commercial credentials. The runtime URL must be loopback. Models are
 * ADMITTED only after inspection: local GGUF weights, not a ":cloud"/remote
 * model, and advertised tool calling. Readiness is then PROBED, never assumed.
 *
 * Token counts are those the runtime reports per call. Ollama's prompt_eval_count
 * INCLUDES tokens reused from the KV cache (verified against Ollama 0.40:
 * 893 prompt tokens reported with 889 cached), so they are split to match the
 * meaning of the Anthropic fields:
 *   input     = prompt_eval_count - prompt_eval_cached_count   (newly evaluated prompt tokens)
 *   cacheRead = prompt_eval_cached_count                       (prompt tokens reused from cache; 0 if not reported)
 *   output    = eval_count                                     (generated tokens, including any thinking)
 * so input + cacheRead + output = total tokens processed in the call.
 * If a count is absent the turn's usage is recorded as missing, not guessed.
 */
import { createHash } from 'node:crypto';
import { createModelAgent } from './agent-loop.mjs';

export const DEFAULT_BASE_URL = 'http://127.0.0.1:11434';
const MIN_LOCAL_WEIGHTS_BYTES = 50 * 1024 * 1024;
const sha256 = (s) => (s ? createHash('sha256').update(String(s), 'utf8').digest('hex') : null);

export class ModelAdmissionError extends Error {}

/** See the header comment: prompt_eval_count includes cached prompt tokens. */
export function normaliseOllamaUsage(data) {
  const cached = typeof data.prompt_eval_cached_count === 'number' ? data.prompt_eval_cached_count : 0;
  return { input: Math.max(0, data.prompt_eval_count - cached), cacheRead: Math.min(cached, data.prompt_eval_count), output: data.eval_count, cacheWrite: 0 };
}

/** Only loopback runtimes are allowed: the lab must not send prompts off the machine. */
export function assertLoopbackRuntime(baseUrl) {
  const u = new URL(baseUrl);
  if (u.protocol !== 'http:') throw new ModelAdmissionError('model runtime must be plain http on loopback');
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)) {
    throw new ModelAdmissionError(`model runtime ${u.hostname} is not loopback; remote inference is not permitted in the lab`);
  }
  if (u.username || u.password || (u.pathname !== '/' && u.pathname !== '')) throw new ModelAdmissionError('model runtime URL must be a bare origin');
  return u.origin;
}

async function call(origin, path, body, { timeoutMs = 600000, fetchImpl = fetch } = {}) {
  const res = await fetchImpl(`${origin}${path}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'error',
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`model runtime ${path} returned ${res.status}: ${text.slice(0, 200)}`);
  return JSON.parse(text);
}

/**
 * Inspect and admit a model. Throws ModelAdmissionError with the reason if refused.
 * @returns identity record for provenance
 */
export async function inspectOllamaModel(model, { baseUrl = DEFAULT_BASE_URL, fetchImpl = fetch } = {}) {
  const origin = assertLoopbackRuntime(baseUrl);
  let version, tags, show;
  try {
    version = (await call(origin, '/api/version', null, { timeoutMs: 5000, fetchImpl })).version ?? null;
    tags = await call(origin, '/api/tags', null, { timeoutMs: 10000, fetchImpl });
  } catch (err) {
    throw new ModelAdmissionError(`local model runtime not available at ${origin}: ${err instanceof Error ? err.message : err}`);
  }
  const tag = (tags.models ?? []).find((m) => m.name === model || m.model === model);
  if (!tag) throw new ModelAdmissionError(`model ${model} is not installed in the local runtime (nothing is pulled automatically)`);
  try {
    show = await call(origin, '/api/show', { model }, { timeoutMs: 30000, fetchImpl });
  } catch (err) {
    throw new ModelAdmissionError(`could not inspect model ${model}: ${err instanceof Error ? err.message : err}`);
  }
  const det = show.details ?? {};
  const reasons = [];
  if (/(:|-)cloud$/i.test(model)) reasons.push('cloud-tagged model (inference would leave the machine)');
  if (show.remote_host || show.remote_model) reasons.push('model is served by a remote host');
  if (det.format !== 'gguf') reasons.push(`weights format "${det.format ?? ''}" is not local GGUF`);
  if (!(tag.size >= MIN_LOCAL_WEIGHTS_BYTES)) reasons.push(`local weights too small (${tag.size} bytes): not a locally stored model`);
  if (!(show.capabilities ?? []).includes('tools')) reasons.push('model does not advertise tool calling');
  if (reasons.length) throw new ModelAdmissionError(`model ${model} refused: ${reasons.join('; ')}`);

  const mi = show.model_info ?? {};
  const ctxKey = Object.keys(mi).find((k) => k.endsWith('.context_length'));
  return {
    name: model,
    digest: tag.digest ?? null,
    sizeBytes: tag.size,
    family: det.family ?? null,
    parameterSize: det.parameter_size ?? null,
    quantization: det.quantization_level ?? null,
    format: det.format,
    parentModel: det.parent_model || null,
    architecture: mi['general.architecture'] ?? null,
    contextLength: ctxKey ? mi[ctxKey] : null,
    capabilities: show.capabilities ?? [],
    modifiedAt: show.modified_at ?? tag.modified_at ?? null,
    modelfileParameters: show.parameters ?? null,
    systemPromptSha256: sha256(show.system),
    hasBuiltInSystemPrompt: Boolean(show.system),
    templateSha256: sha256(show.template),
    runtime: { kind: 'ollama-compatible', origin, version },
  };
}

/**
 * @param {{ model: string, baseUrl?: string, temperature?: number, seed?: number, numCtx?: number,
 *           numPredict?: number, think?: boolean, timeoutMs?: number, identity?: object, fetchImpl?: typeof fetch }} opts
 */
export function createOllamaAdapter(opts) {
  const origin = assertLoopbackRuntime(opts.baseUrl ?? DEFAULT_BASE_URL);
  const fetchImpl = opts.fetchImpl ?? fetch;
  const options = {
    temperature: opts.temperature ?? 0.2,
    seed: opts.seed ?? 0,
    num_ctx: opts.numCtx ?? 16384,
    num_predict: opts.numPredict ?? 1024,
  };
  const think = opts.think ?? false;
  let turnNo = 0;

  return {
    kind: 'ollama',
    name: `ollama:${opts.model}`,
    measuresTokens: true,
    model: opts.model,
    options,
    think,
    describe: () => ({
      provider: 'ollama-compatible (local)',
      model: opts.identity ?? { name: opts.model },
      inference: { ...options, think, stream: false, keepAlive: '15m' },
      tokenSource: 'Ollama /api/chat: input = prompt_eval_count − prompt_eval_cached_count, cacheRead = prompt_eval_cached_count, output = eval_count',
    }),
    start(task, tools) {
      return {
        messages: [{ role: 'user', content: task }],
        tools: tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.schema } })),
      };
    },
    async step(conv) {
      turnNo++;
      const started = performance.now();
      const data = await call(
        origin,
        '/api/chat',
        { model: opts.model, messages: conv.messages, tools: conv.tools, stream: false, think, options, keep_alive: '15m' },
        { timeoutMs: opts.timeoutMs ?? 300000, fetchImpl },
      );
      const msg = data.message ?? { role: 'assistant', content: '' };
      conv.messages.push({ role: 'assistant', content: msg.content ?? '', ...(msg.tool_calls ? { tool_calls: msg.tool_calls } : {}) });
      const hasCounts = typeof data.prompt_eval_count === 'number' && typeof data.eval_count === 'number';
      return {
        model: data.model ?? opts.model,
        stopReason: data.done_reason ?? null,
        durationMs: Math.round(performance.now() - started),
        usage: hasCounts ? normaliseOllamaUsage(data) : null,
        text: msg.content ?? '',
        toolCalls: (msg.tool_calls ?? []).map((tc, i) => {
          let input = tc.function?.arguments ?? {};
          if (typeof input === 'string') {
            try {
              input = JSON.parse(input);
            } catch {
              input = {};
            }
          }
          return { id: tc.id ?? `call_${turnNo}_${i}`, name: tc.function?.name ?? '', input };
        }),
        meta: {
          totalNs: data.total_duration ?? null,
          loadNs: data.load_duration ?? null,
          promptEvalNs: data.prompt_eval_duration ?? null,
          evalNs: data.eval_duration ?? null,
        },
      };
    },
    addResults(conv, _turn, results) {
      for (const r of results) conv.messages.push({ role: 'tool', tool_name: r.call.name, content: r.content });
    },
    nudge(conv, text) {
      conv.messages.push({ role: 'user', content: text });
    },
  };
}

export function createOllamaProvider(opts) {
  const adapter = createOllamaAdapter(opts);
  return Object.assign(createModelAgent(adapter), { model: opts.model, inference: adapter.options, think: adapter.think });
}

/**
 * Readiness probe: one tool-calling request with a trivial instruction.
 * Nothing is executed. Returns { status: 'ready' | 'no-tool-call' | 'malformed' | 'error', ... }.
 */
export async function probeReadiness(opts) {
  const adapter = createOllamaAdapter({ ...opts, numPredict: 256 });
  const conv = adapter.start('Readiness check. Call the http_request tool once with method GET, path /api/v1/health and authorization null. Do nothing else.', [
    {
      name: 'http_request',
      description: 'Send one HTTP request to the lab target.',
      schema: { type: 'object', properties: { method: { type: 'string', enum: ['GET', 'POST'] }, path: { type: 'string' }, authorization: { type: ['string', 'null'] } }, required: ['method', 'path', 'authorization'] },
    },
  ]);
  const started = performance.now();
  try {
    const turn = await adapter.step(conv);
    const call = turn.toolCalls[0];
    const status = !call ? 'no-tool-call' : call.name === 'http_request' && typeof call.input.path === 'string' && call.input.path.startsWith('/') ? 'ready' : 'malformed';
    return { status, latencyMs: Math.round(performance.now() - started), usage: turn.usage, toolCall: call ?? null, text: turn.text.slice(0, 200) };
  } catch (err) {
    return { status: 'error', latencyMs: Math.round(performance.now() - started), error: err instanceof Error ? err.message : String(err) };
  }
}
