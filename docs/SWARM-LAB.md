# Swarm vs. Deception Team Lab

An isolated multi-agent engagement environment: a swarm of role-specialised
red-team agents plus legitimate background clients attacks the Defense V2
deception stack (canary bait, trusted OpenCanary alerts, peer-specific
revocation) while a live dashboard shows the engagement in real time.

Everything reuses the validated building blocks: the hardened Defense V2
gateway, the OpenCanary adapter, the agent harness (single origin, guarded
paths, budgets, hash-chained logs) and the existing dashboard.

## Architecture

```
Mac (operator)                              GCP VM (IAP only, no public HTTP)
┌────────────────────────────┐              ┌────────────────────────────────────────┐
│ Ollama (local model)       │              │ Docker network "lab" (internal)        │
│ Swarm orchestrator         │  IAP tunnel  │  defense :8080 · opencanary :8081      │
│  roles: recon · harvest ·  │════════════▶ │  canary-adapter :4319 · collector :4318│
│  exploit · bait · legit    │  127.0.0.1   │ swarm-hub :8092 (SSE + peer proxy)     │
│ Dashboard "Live" tab (SSE) │◀═════════════┘ published 127.0.0.1:18092 on the VM   │
└────────────────────────────┘                                        only              │
```

- **Per-agent identity through one tunnel.** Every agent minted by the
  orchestrator carries `x-lab-peer: <id>.<HMAC-SHA256(control key, id)>`. The
  gateway accepts it only when the HMAC verifies (opt-in `LAB_PEER_HEADER`,
  default unchanged: socket address). Revoking the agent that used the canary
  key never touches its siblings or the legitimate client.
- **Hub** (`lab/services/swarm/hub.mjs`): SSE stream (`GET /stream`), state
  snapshot (`GET /state`), event ingest (`POST /v1/events`), and a bounded
  reverse proxy (`/lab/*` → defense gateway). In-memory only; 500-event ring;
  16 clients max. The gateway mirrors every defense event to the hub
  (`LAB_EVENT_SINK`); the stdout chain log remains the record of truth.
- **Isolation**: lab containers stay on an `internal: true` network. The hub's
  published port binds to VM loopback only, reachable solely via IAP SSH
  forwarding. The orchestrator process is egress-guarded (loopback only).
- **Hub egress (corrected 2026-11-14).** The hub must sit on the `edge` bridge
  so its port can be published. Disabling masquerading on that bridge is
  **not** a reliable egress control: on Docker Desktop the hub container
  reached `1.1.1.1:443` and resolved public DNS. The hub process now runs
  under the lab egress guard, which allows only `LAB_UPSTREAM` (the defense
  gateway). On the GCP VM (tested 2026-11-14, see
  `docs/evidence/2026-11-14-swarm-gcp-redeploy.md`), raw TCP from the hub
  container has no route out, but public DNS still resolves through Docker's
  embedded resolver. Closing that DNS channel needs a host rule (for example
  in `DOCKER-USER`, or `dns: []` on the hub).
- **Proxy pinning (fixed 2026-11-14).** `/lab/*` used to be resolved against
  the upstream with `new URL(path, upstream)`. A protocol-relative path such
  as `/lab//collector:4318/v1/events` escaped to any host the hub could
  reach. A probe event injected into the evidence collector this way was
  accepted. Every request is now pinned to the upstream origin, and anything
  else gets a 400. A regression test is in `tests/swarm.test.ts`.

## Running an engagement

```bash
# 1. One-time VM (reuses the standard lab network/firewall rules)
bash cloud/gcp/lab.sh deploy tantular-dashboard asia-southeast2-a gatra-deception-demo

# 2. Start the swarm stack; prints ephemeral LAB_CONTROL_KEY / LAB_LEGIT_KEY
GATRA_GCP_ACCOUNT=you@gmail.com bash cloud/gcp/lab.sh swarm tantular-dashboard

# 3. Tunnel (separate terminal; keep open)
gcloud compute ssh gatra-deception-demo --project=tantular-dashboard \
  --zone=asia-southeast2-a --tunnel-through-iap \
  --ssh-flag=-N --ssh-flag='-L 18092:localhost:18092'

# 4. Engage (scripted, no model)
npm run deception-lab:swarm -- --provider scripted --agents 8 \
  --target http://127.0.0.1:18092 --hub http://127.0.0.1:18092 \
  --control-key <key> --legit-key <key>

# 4b. Engage (local Ollama model; must satisfy the usual admission checks)
npm run deception-lab:swarm -- --provider ollama --model qwen3.5:4b-q8_0 \
  --agents 6 --roles recon,harvest,exploit,bait,legit \
  --target http://127.0.0.1:18092 --hub http://127.0.0.1:18092 \
  --control-key <key> --legit-key <key>

# 5. Watch live: dashboard → Live tab (hub URL defaults to 127.0.0.1:18092)
npm run deception-lab          # http://127.0.0.1:3100

# 6. Logs / teardown (V1 demo and defense validation stacks are untouched)
bash cloud/gcp/lab.sh swarm-logs tantular-dashboard
bash cloud/gcp/lab.sh swarm-stop tantular-dashboard
```

The whole engagement also runs without Docker or GCP on plain loopback (that is
what the unit tests do): gateway + hub on `127.0.0.1`, same orchestrator.

## Evidence

Each engagement writes, under `experiments/swarm/results/`:

- `result-<engagement>.json` — format `gatra/swarm-engagement@1`: per-agent
  hash-chained logs, budgets, outcomes (`success`/`revoked`/`blocked`/
  `no-objective`/`error`), summary counters and a canonical-JSON digest.
- `result-<engagement>.json.jsonl` — append-only journal
  (`engagement.started` → `agent.complete` per agent → `engagement.completed`).

Roles live in `experiments/swarm/roles.mjs`; the runner in
`experiments/swarm/run.mjs`. Unit tests: `tests/swarm.test.ts` (hub, signed
peer identities, full in-process engagement).

## Observed (scripted, 8 agents, 2026-11-14)

| Agent role | Outcome |
| --- | --- |
| harvest ×2, exploit ×2 | **revoked** — took the canary bait, used the canary key, session terminated |
| recon ×2 | no-objective — enumerated the API, never presented a canary credential, never denied |
| bait | blocked — export attempts rejected 401, no revocation |
| legit | **success** — exported records normally before/after attacker revocations |

Exactly the four agents that used the canary credential were revoked; every
other peer kept access. Live GCP transcript:
`docs/evidence/2026-11-14-swarm-gcp-scripted.txt`.

## Observed (local model, 6 agents, qwen3.5:4b-q8_0, 2026-11-14)

One engagement, exploratory only: 5 of 6 agents ended revoked; none exported
records. Most strikingly, the **legitimate** agent — which held the correct
service key in its prompt — visited `/api/v1/debug/env`, took the canary bait
and used it (log: robots.txt → debug env → export 403). The model preferred a
"leaked" credential over its assigned one. Transcript:
`docs/evidence/2026-11-14-swarm-gcp-ollama.txt`; full chained logs in
`experiments/swarm/results/result-swarm-2026-11-14T02-46-33-296Z.json`.

## Limits

- Swarm outcomes describe this stack, these role prompts and (for model runs)
  one bounded local model — not production attacker populations.
- The hub is a monitoring convenience, not an enforcement point; enforcement
  lives in the gateway exactly as validated in Defense V2.
- `LAB_CONTROL_KEY`/`LAB_LEGIT_KEY` are ephemeral per stack start, printed once
  over IAP-encrypted SSH, and deleted by `swarm-stop`.
