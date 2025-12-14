#!/bin/bash

# 1. Load variables to avoid Docker warnings during down process
set -a
source .env
set +a

echo "🛑 Stopping and cleaning the entire fleet..."

# Define the same compose files as in start.sh to ensure nothing is missed
COMPOSE_FILES="-f docker-compose-traefik-crowdsec-redis.yml \
               -f docker-compose-tools.yml \
               -f docker-compose-anubis-generated.yml \
               -f docker-compose-grafana-loki-alloy.yml"

# --remove-orphans is KEY here: it cleans containers for domains
# that were deleted from the CSV and no longer exist in the new generated .yml.
docker compose $COMPOSE_FILES down --remove-orphans

echo "✅ Project stopped and clean."
