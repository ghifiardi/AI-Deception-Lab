# Swarm Lab: independent local test (2026-11-14)

This is an independent test of the work described in `HANDOFF-SWARM-LAB.md`. It ran on a local Docker Desktop stack (`lab/swarm.compose.yaml`, ephemeral keys, hub published on `127.0.0.1:18092` only). No GCP resources were used.

## Defects found and fixed

| # | Severity | Defect | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | High | **Hub proxy escape.** `new URL(path, upstream)` let `/lab//collector:4318/v1/events` reach any host the hub can reach. A probe event injected into the evidence collector this way was accepted (HTTP 202, recorded). | Requests are pinned to the upstream origin; anything else gets a 400. | `tests/swarm.test.ts`: fails on the old code, passes on the fix |
| 2 | High | **Hub container egress.** The hub (on the `edge` bridge, masquerade off) connected to `1.1.1.1:443` and resolved public DNS. The defense gateway, which is internal only, was correctly blocked. The GCP evidence `egressBlocked: []` comes from the orchestrator's in-process guard and never tested the hub. | The hub process runs under the lab egress guard, allowing only `LAB_UPSTREAM`. Container-level egress still needs a host firewall rule; on GCP this is untested. | Startup logs the policy |
| 3 | Medium | **Duplicate Live panels.** A stray `initLive()` ran after every experiments re-render, adding a panel and an SSE connection each time. The Live tab also connected on page load and retried forever, causing 500 spam with no hub running. | Initialise once, when the Live tab is first opened; stop retrying if the hub was never reached. | Smoke: "live tab: one panel…" |
| 4 | Medium | **Live tab accepted any hub URL**, for example `https://…`. | `isAllowedHub`: only `/hub` or `http://` to a loopback address. | Unit + smoke |
| 5 | Medium | **Stale live state.** Agent IDs repeat across engagements, so a previous run's agents and outcomes (for example `revoked`) carried over. The hub showed 8 agents during a 6-agent run. | Clear agents on `engagement.started`. | `tests/swarm.test.ts` |
| 6 | Low | **The unit test wrote into the evidence folder** on every suite run. Three such files from this test pass were removed. | `resultsDir` option; the test uses a temporary directory. | Suite leaves `experiments/swarm/results` unchanged |
| 7 | Low | **Stale assertion.** "82/82" was actually 81/82: the test still expected the old loopback default hub. | Test asserts the `/hub` default, a loopback proxy target and the guard. | n/a |

## Results after the fixes

- Unit tests 85/85, typecheck clean, smoke 17/17 (including the new Live tab check).
- All 16 swarm result files on disk verify. The canonical-JSON digest matches and every agent hash chain is intact. 10 are committed: 7 GCP engagements and the 3 local ones below. The other 6 are unit-test output, written by the test bug fixed here, and are not committed.

| Engagement (local Docker) | Outcome |
| --- | --- |
| Scripted, 8 agents (`05-34-34`, repeated `06-05-17` with the dashboard open) | Same as the GCP run: 4 canary users revoked (harvest ×2, exploit ×2), recon ×2 no objective, bait blocked, legit exported. 0 red exports |
| tantular-cyber, 6 agents, `--max-wall-ms 600000` (`05-37-43`) | 0 exports; 3 revoked (harvest, exploit, **recon**); 2 no objective; **legit failed** (6-call budget) |
| Live tab end to end via the `/hub` proxy | Status live, 8 agents, 4 revocations, "Engagement completed", 0 non-loopback requests |

## Observations for the next run

- Raising the wall-clock budget did not change what stopped the agents. Every model agent stopped on its **per-role tool-call budget** (12/12/12/10/6) first. To test capture rather than budget stops, raise `maxToolCalls` per role.
- The legitimate client has failed in all 3 model engagements so far (qwen once, tantular twice on GCP, tantular once locally). It has only 6 tool calls. This is a false-negative risk for the legit baseline, not a defense success.
- Result digests are unkeyed SHA-256. Anyone can edit a file and recompute them. The M2 experiment files are Ed25519-signed; the swarm results are not.
- While the Live tab shows real engagement data, the page watermark still reads "SIMULATED · no outbound connections".
