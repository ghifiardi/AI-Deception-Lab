#!/usr/bin/env bash
# An explicit project is required. "plan" never calls GCP.
set -euo pipefail
ACTION=${1:-plan}
PROJECT=${2:-}
ZONE=${3:-asia-southeast2-a}
NAME=${4:-gatra-deception-demo}
ACCOUNT=${GATRA_GCP_ACCOUNT:-}
# VM auto-stop lifetime. Default 1 hour; long engagements may raise it (max 6 hours).
MAX_RUN=${GATRA_VM_MAX_RUN:-3600s}
gc() {
  if [[ -n "$ACCOUNT" ]]; then gcloud "$@" --account="$ACCOUNT"; else gcloud "$@"; fi
}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
[[ "$PROJECT" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || { echo 'Usage: bash cloud/gcp/lab.sh plan|deploy|demo|validate-defense|swarm|swarm-stop|swarm-logs|logs|cleanup PROJECT [ZONE] [NAME]' >&2; exit 2; }
[[ "$ZONE" =~ ^[a-z]+-[a-z0-9]+[0-9]-[a-z]$ ]] || { echo 'Invalid zone' >&2; exit 2; }
[[ "$NAME" =~ ^[a-z][a-z0-9-]{0,38}[a-z0-9]$ ]] || { echo 'Invalid resource name' >&2; exit 2; }
[[ "$MAX_RUN" =~ ^[0-9]+s$ ]] && (( ${MAX_RUN%s} >= 600 && ${MAX_RUN%s} <= 21600 )) || { echo 'GATRA_VM_MAX_RUN must be 600s..21600s' >&2; exit 2; }
REGION=${ZONE%-*}
NETWORK=$NAME-net
SUBNET=$NAME-subnet
ssh_lab() { gc compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --quiet --ssh-flag=-oConnectTimeout=10 --ssh-flag=-oConnectionAttempts=1 --command="$1"; }
case "$ACTION" in
  plan)
    cat <<EOF
Project: $PROJECT (explicit; gcloud's active project is not changed)
Zone: $ZONE
VM: $NAME, e2-small, Ubuntu 24.04 LTS, 20 GB pd-standard
Lifetime: automatically STOP after $MAX_RUN (GATRA_VM_MAX_RUN; default 3600s); disk remains until cleanup
Network: new $NETWORK / $SUBNET, 10.203.0.0/24, no peering
Access: TCP 22 only from IAP (35.235.240.0/20); no public HTTP
Identity: no VM service account or OAuth scopes; OS Login enabled
Bootstrap: ephemeral external IP for Ubuntu packages and pinned container images
Workloads: internal Docker network, no published ports, existing hardened compose
Demo: compare scripted HTTP sessions, then send a login to real OpenCanary
Evidence: actual service logs; no AI model is included in this small cloud VM
Charges: VM runtime, boot disk, external IPv4 and any billable transfer; not free
Cleanup: bash cloud/gcp/lab.sh cleanup $PROJECT $ZONE $NAME
EOF
    ;;
  deploy)
    # Refuse collisions before creating anything; never adopt an existing network.
    if gc compute networks describe "$NETWORK" --project="$PROJECT" >/dev/null 2>&1; then
      echo "Network $NETWORK already exists. Choose a new NAME; refusing to adopt it." >&2
      exit 1
    fi
    gc services enable compute.googleapis.com iap.googleapis.com oslogin.googleapis.com --project="$PROJECT"
    gc compute networks create "$NETWORK" --project="$PROJECT" --subnet-mode=custom --description='Temporary isolated deception learning lab'
    gc compute networks subnets create "$SUBNET" --project="$PROJECT" --network="$NETWORK" --region="$REGION" --range=10.203.0.0/24
    gc compute firewall-rules create "$NAME-iap" --project="$PROJECT" --network="$NETWORK" --direction=INGRESS --action=ALLOW --rules=tcp:22 --source-ranges=35.235.240.0/20 --target-tags="$NAME"
    gc compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" --machine-type=e2-small --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --boot-disk-size=20GB --boot-disk-type=pd-standard --boot-disk-auto-delete --network="$NETWORK" --subnet="$SUBNET" --tags="$NAME" --no-service-account --no-scopes --metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE --metadata-from-file="startup-script=$HERE/startup.sh" --labels=purpose=deception-learning,temporary=true --max-run-duration="$MAX_RUN" --instance-termination-action=STOP --no-restart-on-failure --shielded-secure-boot
    echo 'VM created. Waiting for SSH and Docker bootstrap (up to 5 minutes).'
    ready=false
    for ((attempt=0; attempt<30; attempt++)); do
      if ssh_lab 'test -f /opt/deception-lab/bootstrap-ready' ; then ready=true; break; fi
      sleep 10
    done
    if [[ "$ready" != true ]]; then
      echo 'Bootstrap not ready. Inspect VM serial output; resources remain for diagnosis. Use cleanup when finished.' >&2
      exit 1
    fi
    BUNDLE=$(mktemp /tmp/gatra-deception-bundle.XXXXXX)
    trap 'rm -f -- "$BUNDLE"' EXIT
    COPYFILE_DISABLE=1 tar -czf "$BUNDLE" -C "$ROOT" lab/compose.yaml lab/defense.compose.yaml lab/services lab/opencanary cloud/gcp/remote-demo.sh cloud/gcp/validate-defense.sh
    gc compute scp "$BUNDLE" "$NAME:/tmp/gatra-deception-lab.tar.gz" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --quiet
    if [[ "${GATRA_SKIP_REMOTE_DEMO:-0}" == 1 ]]; then
      ssh_lab 'sudo tar -xzf /tmp/gatra-deception-lab.tar.gz -C /opt/deception-lab'
      echo 'Dashboard preparation: legacy HTTP demo skipped; swarm setup will run next.'
    else
      ssh_lab 'sudo tar -xzf /tmp/gatra-deception-lab.tar.gz -C /opt/deception-lab && sudo bash /opt/deception-lab/cloud/gcp/remote-demo.sh'
    fi
    echo "Repeat: bash cloud/gcp/lab.sh demo $PROJECT $ZONE $NAME"
    ;;
  demo) ssh_lab 'sudo bash /opt/deception-lab/cloud/gcp/remote-demo.sh' ;;
  validate-defense) ssh_lab 'sudo bash /opt/deception-lab/cloud/gcp/validate-defense.sh' ;;
  swarm)
    DEFENSE_MODE=${GATRA_DEFENSE_MODE:-defended}
    [[ "$DEFENSE_MODE" =~ ^(baseline|hardened|defended)$ ]] || { echo 'GATRA_DEFENSE_MODE must be baseline|hardened|defended' >&2; exit 2; }
    # Upload the swarm stack (hub + engage script) and start an engagement lab.
    BUNDLE=$(mktemp /tmp/gatra-swarm-bundle.XXXXXX)
    trap 'rm -f -- "$BUNDLE"' EXIT
    COPYFILE_DISABLE=1 tar -czf "$BUNDLE" -C "$ROOT" lab/swarm.compose.yaml lab/services cloud/gcp/swarm-engage.sh
    gc compute scp "$BUNDLE" "$NAME:/tmp/gatra-swarm-bundle.tar.gz" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --quiet
    ssh_lab "sudo tar -xzf /tmp/gatra-swarm-bundle.tar.gz -C /opt/deception-lab && sudo bash /opt/deception-lab/cloud/gcp/swarm-engage.sh start $DEFENSE_MODE"
    echo
    echo "On your machine:"
    echo "  gcloud compute ssh $NAME --project=$PROJECT --zone=$ZONE --tunnel-through-iap --ssh-flag=-N --ssh-flag='-L 18092:localhost:18092'"
    echo "  npm run deception-lab:swarm -- --provider scripted --target http://127.0.0.1:18092 --hub http://127.0.0.1:18092 --control-key <key> --legit-key <key>"
    echo "  npm run deception-lab   # dashboard Live tab at http://127.0.0.1:3100"
    ;;
  swarm-stop) ssh_lab 'sudo bash /opt/deception-lab/cloud/gcp/swarm-engage.sh stop' ;;
  swarm-logs) ssh_lab 'sudo bash /opt/deception-lab/cloud/gcp/swarm-engage.sh logs' ;;
  logs) ssh_lab 'sudo docker compose -p gatra-cloud-demo -f /opt/deception-lab/lab/compose.yaml --profile opencanary logs --tail=100 collector honeypot canary-adapter opencanary' ;;
  cleanup)
    # Only explicitly named lab resources; no wildcard or project deletion.
    gc compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet
    gc compute firewall-rules delete "$NAME-iap" --project="$PROJECT" --quiet
    gc compute networks subnets delete "$SUBNET" --project="$PROJECT" --region="$REGION" --quiet
    gc compute networks delete "$NETWORK" --project="$PROJECT" --quiet
    ;;
  *) echo "Unknown action: $ACTION" >&2; exit 2 ;;
esac
