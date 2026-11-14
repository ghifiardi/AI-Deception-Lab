# GATRA Deception Lab: design note and threat model

| Milestone | Scope |
| --- | --- |
| 1 | Browser simulator: scenarios, policy engine, containment controller, demo |
| 1.5 | Runtime-validated container isolation, human-in-the-loop decisions, SHA-256 integrity, live lab target, experiment runner |
| 2 | Research platform for agentic AI attackers: provider-independent attacker interface, local models (Ollama-compatible, including Tantular Cyber), process egress guard, outcome taxonomy, statistics with uncertainty, signed provenance, optional OpenCanary |

## 1. What exists in the repository

| Area | Finding | Consequence for this lab |
| --- | --- | --- |
| Stack | Vite 6 + vanilla TypeScript, deployed to Vercel from `main`. | The lab is a separate Vite page with its own config, outside the production build and deploy. |
| GATRA agents | `src/types` defines ADA/TAA/CRA/CLA/RVA; `src/gatra/connector.ts` keeps its live API path disabled (`fetchFromGatraAPI` returns `null`). | Roles are simulated and labelled so. Nothing imports `src/gatra`; live connectors stay disabled and untouched. |
| Tests | `node --test` + Playwright. | Unit tests use Node's TypeScript stripping; UI smoke test is a standalone Playwright script. |

## 2. Architecture

```text
 ┌──────────────────────── browser (default, offline) ────────────────────────────┐
 │ simulator: compileRun() → SHA-256 chained events → deriveState → UI (SYNTHETIC) │
 │ Experiments tab: bundled/loaded results (MEASURED), chain + Ed25519 verified    │
 └─────────────────────────────────────────────────────────────────────────────────┘

 ┌──────────── host: experiment runner (one Node process, egress-guarded) ─────────────┐
 │                                                                                      │
 │  provider adapters          agent loop (identical for every provider)                 │
 │  ┌─────────────┐   step()   ┌──────────────────────────────────────┐   http(path)     │
 │  │ scripted    │──────────▶ │ task prompt · 2 tools · nudge rule    │ ───────────────┐ │
 │  │ ollama      │ ◀── usage  │ budgets · SHA-256 action log          │                │ │
 │  │ claude      │            └──────────────────────────────────────┘                ▼ │
 │  └─────┬───────┘                                       guard: one loopback origin      │
 │        │ loopback only                          target.mjs on 127.0.0.1:<ephemeral>   │
 │        ▼                                        (none / static / adaptive + lab       │
 │  Ollama-compatible runtime :11434               containment, ground-truth state)      │
 │  (local GGUF only; cloud models refused)                                              │
 │                                                                                      │
 │  egress guard (net.Socket.connect): loopback ✔ · api.anthropic.com:443 only for       │
 │  --provider claude --yes · everything else refused and recorded                       │
 │  results/*.json: design, provenance, runs + logs, stats, Ed25519 checkpoints          │
 └──────────────────────────────────────────────────────────────────────────────────────┘

 ┌──────── Docker network `lab_internal` (internal: true), validated 50/50 (+10 with OpenCanary) ───────┐
 │ honeypot (target.mjs) → collector ← canary-adapter ← opencanary (profile "opencanary", off by default) │
 │ driver (scripted agent + same guard) · all non-root, read-only, cap_drop ALL, limits, no ports       │
 └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Module | Responsibility |
| --- | --- |
| `src/engine/*` | Pure simulator and SHA-256 |
| `src/ui/*` | Simulator UI, interactive analyst, Experiments dashboard (in-browser chain and Ed25519 verification) |
| `lab/services/target.mjs` | Live mock API, deception modes, lab containment, ground truth and timings |
| `lab/services/guard.mjs`, `harness.mjs` | Single-origin guard; budgets; SHA-256 action log; token accounting from reported usage only |
| `lab/services/egress-guard.mjs` | In-process egress control for the runner |
| `lab/services/canary-adapter.mjs`, `lab/opencanary/` | OpenCanary normalisation with credential redaction; hardened config |
| `experiments/providers/agent-loop.mjs` | Provider-independent attacker loop (prompt, tools, dispatch, nudges) |
| `experiments/providers/{claude,ollama}.mjs` | Adapters; Ollama admission and readiness probe |
| `experiments/run.mjs`, `stats.mjs`, `provenance.mjs` | Runner, outcome classes, statistics, pre-registration, environment, signing |
| `scripts/verify-log.ts`, `scripts/validate-lab.mjs` | Independent verification; container validation |

## 3. Integrity and provenance

**Hash chains.** Every simulator event, agent action and target event is SHA-256 chained: `hash = SHA-256(canonical JSON without hash)`, linked through `prevHash`. The browser and `npm run deception-lab:verify` check this independently.

**Signed checkpoints (milestone 2).** The runner signs with Ed25519 (`node:crypto`):

- **After each run:** a checkpoint `{experimentId, runIndex, trial, mode, seed, logHead, prevCheckpointSha256, signedAt}`. The checkpoints chain to each other.
- **At the end:** a signature over the SHA-256 of the whole result, excluding the signing block.

This catches edits that leave hash chains intact, for example changing a summary (tested).

**Keys.** The private key is created on first use at `~/.config/gatra-deception-lab/signing-ed25519.pem` (mode 0600, outside the repository; override with `LAB_SIGNING_KEY`). Results embed only the public key and its fingerprint. Verify with `npm run deception-lab:verify -- result.json --pin SHA256:<fingerprint>`.

**Provenance recorded per experiment:**

- git commit and dirty flag, captured at start
- Node version, OS, CPU and memory
- for local models: name, digest, size, family, parameter count, quantisation, context length, capabilities, Modelfile parameters, and hashes of the built-in system prompt and template; plus runtime version
- inference settings
- readiness probe result
- egress policy and every blocked attempt
- pre-registration file hash and match result
- config hash
- cost model

**Limitations of the signing:**

- **Identity.** A self-generated key proves "unchanged since signed by the holder of this key", not who the holder is. Pin the fingerprint out of band, or use an organisational key held in a KMS or HSM.
- **Key custody.** Anyone with the private key file can sign anything.
- **Time.** `signedAt` comes from the local clock; there is no RFC 3161 timestamp.
- **Anchoring.** Checkpoints are not anchored externally, so a holder could re-run and re-sign; a transparency log or WORM store would prevent this.
- **Browser exports.** Simulator exports from the browser are hash-chained but unsigned; the browser holds no key.

## 4. Human-in-the-loop analyst

Unchanged from milestone 1.5: Approve, Reject or Keep observing, recorded as explicit replayable inputs and events.

## 5. Attacker providers (milestone 2)

- **One loop, many models.** `agent-loop.mjs` owns everything that must be identical across models: the task prompt, the two tools (`http_request(method, path, authorization)` and `submit_answer(export_id)`), dispatch through the harness, at most two plain reminders when a model replies without a tool call, and how a run ends. Adapters only translate messages and report usage.
- **Local models (Ollama-compatible).** Admission requires all of:
  - a loopback runtime URL
  - an installed model (nothing is pulled automatically)
  - local GGUF weights of at least 50 MB
  - no `:cloud` or remote serving
  - advertised tool calling

  Then a readiness probe asks for one tool call; experiments refuse to start unless it returns `ready`. On this machine, the cloud entries listed by the runtime (`glm-5.3:cloud`, `qwen3.5:cloud`) are refused by this rule.
- **Token semantics.** Measured, never estimated. Ollama's `prompt_eval_count` includes KV-cache reuse (verified on Ollama 0.40: 893 reported, 889 cached). Counts are split so that the fields mean the same thing as Anthropic's:

  | Field | Ollama | Anthropic |
  | --- | --- | --- |
  | input (new prompt tokens) | `prompt_eval_count − prompt_eval_cached_count` | `input_tokens` |
  | cacheRead | `prompt_eval_cached_count` | `cache_read_input_tokens` |
  | output | `eval_count` | `output_tokens` |

  A turn without counts is recorded as missing, and the run's coverage becomes `partial`.
- **Commercial models.** The Claude adapter is unchanged in behaviour. It is used only with `--yes`, and its API host is the only non-loopback destination the egress guard will allow, and only for that provider.

## 6. Trust boundaries

| ID | Boundary | Controls | Validated by |
| --- | --- | --- | --- |
| TB1 | Browser demo ↔ network | No network APIs in `src/`; CSP; results bundled or read from a local file | Unit scan; smoke test (no non-loopback requests) |
| TB2 | Containers ↔ host | Non-root, read-only, cap_drop ALL, no-new-privileges, limits, no socket, no credentials | `validate-lab` (50 checks) |
| TB3 | Lab network ↔ outside | `internal: true`, no published ports | `validate-lab` egress/DNS checks plus negative control |
| TB4 | Agent ↔ targets | Path-only tool, single-origin guard, no redirects | Guard tests; container driver |
| TB5 | Runner ↔ commercial model API | Only `--provider claude --yes`; exact host:port allowed by the egress guard | Egress guard tests |
| TB6 | Lab authority ↔ human authority | Lab-scoped actions; dry-run proposals; interactive analyst | Containment tests |
| TB7 | Runner ↔ local model runtime | Loopback-only runtime URL; model admission; readiness probe; runner process egress guard (loopback only for local providers) | Admission, readiness and egress tests; blocked attempts recorded per experiment |
| TB8 | OpenCanary ↔ lab | Optional profile (off by default); non-root twistd (no sudo wrapper); read-only; all caps dropped; internal network only; webhook to in-lab adapter only; raw credentials never logged | `validate-lab --opencanary` (60 checks incl. redaction) |

**Residual risk on TB7.** The egress guard controls the runner process, not the Ollama daemon. The daemon is a separate host process that can reach the internet (for pulls and cloud models). The lab never asks it to pull, and refuses cloud or remote models, so no lab traffic should leave the host. But this is enforced by admission rules, not by network isolation of the daemon. For stronger guarantees, run the model runtime in its own internal-only container or on an air-gapped host.

## 7. Threat model

| Threat | Mitigation | Evidence |
| --- | --- | --- |
| Agent targets something other than the lab | Path-only tool, single-origin guard, no redirects | 17 guard escape tests; blocked calls logged |
| Agent or provider code opens a connection directly, bypassing the tool | Process egress guard; attempts recorded in provenance | Test: direct `fetch('http://1.1.1.1')` inside a provider is blocked and recorded |
| Prompts or data sent to a remote model unintentionally | Loopback-only runtime; cloud and remote models refused; commercial provider needs `--yes` | Admission tests (cloud, remote URL, no-tools) |
| Model not ready or wrong model | Readiness probe; model digest and system-prompt hash recorded | Readiness tests; provenance |
| Token figures inflated, deflated or invented | Usage only from the runtime or API; cache-split verified; missing marked | Cache-split and missing-usage tests; double-count bug found and fixed during milestone 2 |
| Objective failure reported as containment | Outcome classes: success / contained / deceived / refused / failed / invalid | Classification test |
| Over-claiming results | Wilson, Newcombe and bootstrap intervals; exploratory unless pre-registered, n ≥ 20, CI excludes 0, logs verify, ≤10% invalid | Statistics tests (reference values); pre-registration tests |
| Tampered results | Hash chains + Ed25519 checkpoints and final signature; pinning | Signature tamper tests; CLI and browser verification |
| Credential capture by the decoy | OpenCanary credentials reduced to username hash + password length; console handler removed | `OC-redaction` runtime check |
| OpenCanary compromise | Non-root, read-only, no caps, internal network, limits | `validate-lab --opencanary` |
| Runaway runtime or cost | Tool, token, wall-time, turn and byte budgets; abort on fatal provider errors | Harness tests |
| Live GATRA connectors enabled | Untouched; not imported | `git diff main -- src api server` is empty |

## 8. Assumptions and limitations

See [METHODOLOGY.md](METHODOLOGY.md) for experimental validity.

- The live target is one small mock API; real environments, real attackers and real decoy platforms behave differently.
- The local-model runtime's own network access is outside the lab's control (TB7).
- Container validation ran on Docker Desktop for macOS (arm64, cgroup v2) only.
- Signing uses a self-managed key (see §3).
- No commercial-model experiment has been run; the configured Anthropic account had no credit, and none was attempted in milestone 2.
