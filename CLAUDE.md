# CLAUDE.md

Guidance for coding agents working in this repo. See [README.md](README.md) for the full overview and [PUBLISHING-AUDIT.md](PUBLISHING-AUDIT.md) for what was redacted before publication.

## What this repo is

The GATRA Deception Lab: a browser simulator, an experiment runner and a container lab for studying credential deception against LLM agents. It also holds the source of the *Optional Traps* paper (`paper/`) and the evidence behind it.

## Layout

- `src/` – TypeScript simulator: `engine/` (deterministic simulator, hashing, policy, metrics) and `ui/` (browser panels).
- `tests/` – `*.test.ts` suites run with `node --test`.
- `scripts/` – smoke, validation, log/defense verification and demo-recording scripts.
- `experiments/` – experiment runners, providers, stats, `defense/` and `swarm/` studies, plus archived results.
- `lab/` – Docker Compose definitions, OpenCanary config and lab services.
- `docs/` – design, methodology, swarm notes, archived `evidence/`, and the static `game/` and `maze/` pages.
- `paper/` – LaTeX source and preprint PDF of the paper.
- `cloud/` – GCP live-demo material.

## Checks a change must pass (same as CI)

Node 22.6 or later is required (`engines.node`).

```
npm ci
npm run deception-lab:typecheck   # tsc -p .
npm test                          # runs test:deception-lab
```

## Hard rules

- **Never modify archived evidence**: `experiments/results/`, `experiments/defense/result-*.json`, `experiments/defense/source-snapshots/`, `experiments/swarm/results/`, `experiments/preregistration/`, `docs/evidence/`. They are signed or digest-checked and back the paper.
- **Don't run experiments, studies, swarms or recordings**, or anything needing Ollama, Docker or a model provider (`deception-lab:experiment`, `:defense-study`, `:swarm*`, `:record`). Never pass `--provider claude --yes`. They cost money and can overwrite evidence; typecheck and tests are enough.
- **Keep credentials, keys and tokens synthetic** in code, fixtures and docs (e.g. `LABKEY-…`). Keep addresses to documentation ranges (RFC 5737) or reserved names. Real ones must never be committed.
- **Network stays loopback or internal-only.** Don't add code reaching external hosts or enable live GATRA connectors; this is a deception lab and must not touch real systems.
- **No personal details or absolute local paths** (`/Users/...`) in committed files (see `PUBLISHING-AUDIT.md`).
- **Don't commit large media or build output** (`recordings/*.mp4`, `*.webm`, `dist/`) and don't touch `_private/`; all are git-ignored to avoid bloat and leaks.
- **If a change would alter the paper's claims or reproduction steps, stop** and say so in the PR rather than editing `paper/`.

## Conventions visible in the code

- ESM only (`"type": "module"`); TypeScript is strict, with `noUncheckedIndexedAccess`, `noUnusedLocals` and `noUnusedParameters` (`tsconfig.json`).
- `erasableSyntaxOnly` and `verbatimModuleSyntax`: no enums or parameter properties; use `import type` for type-only imports.
- Relative imports include the `.ts` extension (e.g. `../src/engine/simulator.ts`); tests run directly via `--experimental-strip-types`.
- Tests live in `tests/<topic>.test.ts`, use `node:test` with `node:assert/strict`, and are picked up by the `tests/*.test.ts` glob.
- Runs are seeded and deterministic; tests assert replays are identical (see `tests/replay.test.ts`).
- Experiment and script entry points are `.mjs`; only `scripts/verify-log.ts` is type-checked among scripts.
