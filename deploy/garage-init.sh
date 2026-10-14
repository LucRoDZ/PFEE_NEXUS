#!/bin/sh
# One-time Garage setup: layout, access key, bucket. Run after `docker compose up -d garage`.
set -eu
G="docker compose -f deploy/docker-compose.yml exec -T garage /garage"
NODE=$($G status | awk '/NO ROLE ASSIGNED|HEALTHY/ {print $1; exit}')
$G layout assign -z dc1 -c 10G "$NODE"
$G layout apply --version 1
$G key import --yes -n nexus "$NEXUS_S3_ACCESS_KEY" "$NEXUS_S3_SECRET_KEY"
$G bucket create nexus-objects
$G bucket allow --read --write --owner nexus-objects --key nexus
