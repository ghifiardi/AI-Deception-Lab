/**
 * Claude adapter (Anthropic Messages API via the official SDK).
 * Commercial: only used with --provider claude --yes. Never needed for local-model experiments.
 */
import Anthropic from '@anthropic-ai/sdk';
import { createRequire } from 'node:module';
import { FatalProviderError } from '../../lab/services/harness.mjs';
import { createModelAgent } from './agent-loop.mjs';

export const DEFAULT_MODEL = 'claude-opus-5-5';
export const API_HOST = { host: 'api.anthropic.com', port: 443 };

function sdkVersion() {
  try {
    return createRequire(import.meta.url)('@anthropic-ai/sdk/package.json').version;
  } catch {
    return null;
  }
}

/**
 * @param {{ model?: string, effort?: string, fallbacks?: boolean, client?: any }} [opts]
 */
export function createClaudeAdapter(opts = {}) {
  const model = opts.model ?? DEFAULT_MODEL;
  const effort = opts.effort ?? 'medium';
  const useFallbacks = opts.fallbacks ?? true;
  const client = opts.client ?? new Anthropic();
  const served = new Set();

  return {
    kind: 'claude',
    name: `claude:${model}`,
    measuresTokens: true,
    model,
    effort,
    fallbacks: useFallbacks,
    describe: () => ({
      provider: 'anthropic',
      model: { requested: model, served: [...served] },
      inference: { effort, maxTokensPerTurn: 16000, serverSideFallbacks: useFallbacks, promptCaching: 'automatic (ephemeral)' },
      runtime: { sdk: '@anthropic-ai/sdk', sdkVersion: sdkVersion() },
      tokenSource: 'Anthropic Messages API response.usage (input, output, cache read, cache write)',
    }),
    start(task, tools) {
      return {
        messages: [{ role: 'user', content: task }],
        tools: tools.map((t) => ({ name: t.name, description: t.description, strict: true, input_schema: t.schema })),
      };
    },
    async step(conv, { tokensLeft }) {
      const params = {
        model,
        max_tokens: Math.max(1024, Math.min(16000, tokensLeft ?? 16000)),
        output_config: { effort },
        cache_control: { type: 'ephemeral' },
        tools: conv.tools,
        messages: conv.messages,
      };
      if (useFallbacks) {
        params.betas = ['server-side-fallback-2026-07-01'];
        params.fallbacks = 'default';
      }
      const started = performance.now();
      let response;
      try {
        response = await client.beta.messages.create(params);
      } catch (err) {
        if (err instanceof Anthropic.AuthenticationError) throw new FatalProviderError('provider authentication failed');
        if (err instanceof Anthropic.PermissionDeniedError) throw new FatalProviderError('provider permission denied');
        if (err instanceof Anthropic.BadRequestError) throw new FatalProviderError(`provider rejected request: ${err.message}`);
        if (err instanceof Anthropic.RateLimitError) throw new Error('rate limited by provider (after SDK retries)');
        if (err instanceof Anthropic.APIError) throw new Error(`provider API error ${err.status}`);
        throw err;
      }
      served.add(response.model);
      const u = response.usage ?? {};
      const turn = {
        model: response.model,
        stopReason: response.stop_reason,
        fallback: (u.iterations ?? []).some((it) => it.type === 'fallback_message'),
        durationMs: Math.round(performance.now() - started),
        usage:
          typeof u.input_tokens === 'number' && typeof u.output_tokens === 'number'
            ? { input: u.input_tokens, output: u.output_tokens, cacheRead: u.cache_read_input_tokens ?? 0, cacheWrite: u.cache_creation_input_tokens ?? 0 }
            : null,
        toolCalls: [],
        text: '',
      };
      if (response.stop_reason === 'refusal') {
        turn.refusal = response.stop_details?.category ?? 'refusal';
        return turn;
      }
      conv.messages.push({ role: 'assistant', content: response.content });
      for (const b of response.content) {
        if (b.type === 'tool_use') turn.toolCalls.push({ id: b.id, name: b.name, input: b.input });
        if (b.type === 'text') turn.text += b.text;
      }
      return turn;
    },
    addResults(conv, _turn, results) {
      conv.messages.push({
        role: 'user',
        content: results.map((r) => ({ type: 'tool_result', tool_use_id: r.call.id, content: r.content, is_error: r.isError })),
      });
    },
    nudge(conv, text) {
      conv.messages.push({ role: 'user', content: text });
    },
  };
}

export function createClaudeProvider(opts = {}) {
  const adapter = createClaudeAdapter(opts);
  return Object.assign(createModelAgent(adapter), { model: adapter.model, effort: adapter.effort, fallbacks: adapter.fallbacks });
}
