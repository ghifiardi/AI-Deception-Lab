#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
dc() { docker compose -p gatra-cloud-demo -f lab/compose.yaml --profile opencanary "$@"; }
for mode in none static adaptive; do
  export LAB_MODE=$mode
  echo "=== REAL HTTP SESSION: deception=$mode; deterministic driver, synthetic records ==="
  dc up -d --force-recreate collector honeypot
  # Driver waits for startup itself. A failure stops the demo with its actual error.
  dc run --rm driver
  dc logs --no-color honeypot collector
done
echo '=== REAL OPENCANARY: page view and synthetic login ==='
dc up -d canary-adapter opencanary
for ((attempt=0; attempt<30; attempt++)); do
  # Readiness uses the internal network, not a public endpoint.
  if dc exec -T collector node -e 'fetch("http://opencanary:8081/index.html", {signal:AbortSignal.timeout(2000)}).then(r=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))'; then break; fi
  if ((attempt==29)); then echo 'OpenCanary not ready' >&2; exit 1; fi
  sleep 2
done
dc exec -T collector node -e 'fetch("http://opencanary:8081/index.html",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:"username=labuser&password=Synthetic-Pass-123",signal:AbortSignal.timeout(5000)}).then(r=>{console.log("Actual login response:",r.status);if(r.status!==200)process.exit(1)}).catch(e=>{console.error(e);process.exit(1)})'
sleep 3
events=$(dc logs --no-color canary-adapter collector)
printf '%s\n' "$events"
grep -q '"kind":"http.login-attempt"' <<< "$events"
grep -q '"collector_seq".*"source":"opencanary".*"kind":"http.login-attempt"' <<< "$events"
if grep -q 'Synthetic-Pass-123' <<< "$events"; then
  echo 'FAIL: submitted password appeared in telemetry' >&2
  exit 1
fi
echo 'Expected: http.get and http.login-attempt, followed by collector events.'
echo 'OpenCanary alerts are collected only. It does not trigger network containment here.'
echo 'Decoy containers have no published ports and use the internal-only Docker network.'
