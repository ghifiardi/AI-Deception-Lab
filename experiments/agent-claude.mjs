// Backwards-compatible entry point (milestone 1.5). The implementation now lives in providers/claude.mjs.
export { TASK_PROMPT } from './providers/agent-loop.mjs';
export { DEFAULT_MODEL, createClaudeProvider, createClaudeAdapter } from './providers/claude.mjs';
