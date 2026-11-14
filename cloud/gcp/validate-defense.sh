#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
# Generated per validation run; never copy user/project credentials into the lab.
secret_file=$(mktemp /tmp/gatra-defense-keys.XXXXXX)
chmod 600 "$secret_file"
trap 'rm -f -- "$secret_file"' EXIT
python3 - "$secret_file" <<'PY'
import secrets, sys
from pathlib import Path
Path(sys.argv[1]).write_text('LAB_CONTROL_KEY='+secrets.token_hex(32)+'\nLAB_LEGIT_KEY=LABKEY-'+secrets.token_hex(16).upper()+'\n')
PY
dc() { docker compose -p gatra-defense-v2 --env-file "$secret_file" -f lab/defense.compose.yaml "$@"; }
dc up -d --force-recreate collector defense canary-adapter opencanary attacker bypass legitimate
result=0
dc run --rm verifier || result=$?
dc logs --no-color defense canary-adapter collector
# These containers are test-only. Remove the whole dedicated project after evidence.
dc down
exit "$result"
