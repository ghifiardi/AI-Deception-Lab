# Demo storyboard (4:24)

> This script is for the in-app recorder (`npm run deception-lab:record`). The separate 10-minute audience walkthrough, which adds the live GCP V1 demo and Defense V2, is `docs/gatra-deception-lab-walkthrough.mp4`; its chapters and talk track are in [the audience guide](<GATRA Deception Lab — Audience Guide.md#video-walkthrough>).

Source of truth: `src/ui/director.ts` (`DEMO_SHOTS`). Captions are keyed to real events in each compiled run (seed 42), so the narration always matches what is on screen. Playback holds about 3.2 s on every narrated event. The corner watermark reads SIMULATED throughout, except during shots 9 and 10, where it switches to MEASURED.

Start times below were measured by `npm run deception-lab:record` (written to `recordings/timecodes.txt`); expect ±5 s between machines.

| # | Start | Shot | Camera | Caption / voice-over |
| --- | --- | --- | --- | --- |
| 1 | 0:00 | Title card | Full view | "A synthetic attacker meets decoys inside an isolated lab. The scenarios are simulated in this browser. The measured results near the end come from a local mock lab. Nothing touches production." |
| 2 | 0:09 | Topology tour | All → deception → egress → agents | Zones left to right; hatched zone sealed with no route to production; default-deny egress with only telemetry allowed; simulated GATRA agent roles plus policy and analyst. |
| 3 | 0:36 | Scenario a: API honeypot and canary (adaptive) | Entry → deception → agents → entry → agents → all | Client probes the API, finds the honeypot, is throttled (`R-DECOY-01`), receives a synthetic canary and uses it; `R-CANARY-01` contains; the external block stays a dry-run proposal; the export never runs. |
| 4 | 1:27 | Economics: scenario a (Synthetic) | Overlay | "Same seed, three modes. Without decoys the client reaches its objective. With decoys it never touches the real target." |
| 5 | 1:40 | Scenario b: false-positive safeguard, **human in the loop** (static) | Entry → deception → agents → all | Approved scanner touches decoys; `R-SAFE-00` suppresses automation; **playback stops** with Approve / Reject / Keep observing; the analyst rejects; the decision is a SHA-256 chained event and the run replays exactly. |
| 6 | 2:10 | Scenario c: instrumented agent (adaptive) | All → entry → deception → all → agents | Hard limits stated; tokens measured because instrumented; adaptive decoys offer leads; harness stops the agent at the token bound; session closed and audit sealed. |
| 7 | 2:53 | Economics: scenario c (Synthetic) | Overlay | "In this fixture, adaptive decoys raised the agent's tool calls and tokens. That is one measured run testing a hypothesis, not a guarantee." |
| 8 | 3:05 | Scenario d: egress denied (adaptive) | Deception → egress → agents → egress | Foothold on decoy workload; outbound call denied by default; workload quarantined and gateway sealed (`R-EGRESS-01`); collector-lookalike host also denied. |
| 9 | 3:48 | **Measured: local cyber-tuned model** | Overlay, watermark MEASURED | Pre-registered M2-TC-v1 (Tantular Cyber 9.7B on local Ollama, 20 trials per mode, Ed25519 signature verified in the browser, 0 egress attempts): "Measured: a local cyber-tuned model attacked the lab target with no, static and adaptive deception, under the same seeds and budgets. No commercial API was involved." |
| 10 | 4:00 | **Measured: outcome taxonomy and intervals** | Overlay, watermark MEASURED | Outcome bars (1/19; 9/8/3; 13/4/3) and the rates table: "Outcomes keep success, containment and deception apart. Every difference carries a 95% interval and is labelled exploratory unless pre-registered, adequately powered and clear of zero." |
| 11 | 4:12 | Closing card | Full view | Decisions trace to evidence and rules in a SHA-256 chain; only lab-scoped actions run; tokens only when instrumented; local models run with no commercial credentials, no outbound connections and signed records; measured and synthetic values labelled apart. |
| | 4:24 | End | | |

## Recording checklist

1. `npm ci` (once), then `npm run deception-lab:record`. Output goes to `deception-lab/recordings/gatra-deception-lab-demo.{webm,mp4}` at 1920×1080.
2. Without Playwright's bundled Chromium, the recorder opens a visible Google Chrome window. Leave it alone until it closes. `npx playwright install chromium` lets it run headless.
3. Manual option: run `npm run deception-lab`, open `http://127.0.0.1:3100/?demo=1` in a 1920×1080 browser window, and record with QuickTime or OBS. Press <kbd>Esc</kbd> to stop.
4. If you add a voice-over, read the captions as written. They avoid performance claims on purpose.
