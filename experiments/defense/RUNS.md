# Defense V2 evidence index

## Interrupted candidate

`result-2026-11-13T07-54-09-460Z.json.jsonl` records the initial candidate's
locally frozen protocol, source fingerprints, and completed sessions. The run
was interrupted after source review identified inheritance of V1's global
canary/session-denial mechanism. It is incomplete and excluded from final
validation. Its observations are retained rather than silently replaced.

## Corrected candidate

`result-2026-11-13T07-57-58-061Z.json.jsonl` is the incremental journal for the
corrected defense. The matching [final JSON](result-2026-11-13T07-57-58-061Z.json) is complete:
20/20 baseline successes, 0/20 hardened, 0/20 defended, with all 60 sessions
valid. Defended sessions revoked 19/20 peers; trial 11 failed without revocation. Failed outcomes and invalid
sessions are retained; there is no replacement sampling or early result-based
stopping.

The protocol has not been externally preregistered. See
[`protocol.json`](protocol.json) and the
[validation report](../../docs/VALIDATED-DEFENSE.md) for the claim boundaries.

The exact paired baseline-versus-defended p-value is 0.0000019073486328125;
hardened-versus-defended p = 1. Hardening alone also prevented all exports, so
there is no demonstrated incremental prevention from deception.

The measured gateway is preserved as
[source snapshot](source-snapshots/72f6fda3d6f917dabb176a729f6949f7ce309f40a8d7805d8e292c9ca3925ea2.txt).
Current code adds TTL renewal/cleanup, supplied-key startup validation and HTTP
input/method rejection. Those later edits passed separate regression and final
GCP integration checks; they were not measured by this study. The result verifier
explicitly reports snapshot fallback and validates all 60 sessions/120 chains,
recorded source digests, Wilson intervals and exact paired statistics.
