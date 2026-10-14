#!/usr/bin/env bash
# G4 on one machine with Docker: the HDG network is "internal", so nothing on it
# can reach the internet. A control run on Docker's default network shows the
# same probe does reach the internet when it is allowed to.
# On the k3s cluster use instead:
#   kubectl -n hdg exec deploy/data-api -- python demo/egress_probe.py
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p var
echo "building the NEXUS image..."
docker build -q -t nexus-poc:0.1 -f deploy/Dockerfile . >/dev/null
docker network inspect nexus-hdg >/dev/null 2>&1 || docker network create --internal nexus-hdg >/dev/null
echo "control, default network (internet allowed):"
docker run --rm nexus-poc:0.1 python demo/egress_probe.py | tee var/g4-control.json || true
echo "HDG network (internal: all outbound traffic denied):"
docker run --rm --network nexus-hdg nexus-poc:0.1 python demo/egress_probe.py | tee var/g4.json
