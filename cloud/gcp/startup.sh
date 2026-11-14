#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io docker-compose-v2
systemctl enable --now docker
install -d -m 0755 /opt/deception-lab
touch /opt/deception-lab/bootstrap-ready
