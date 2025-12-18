#!/bin/bash

# =============================================================================
# stop.sh - Stack Shutdown Script
# =============================================================================
# Stops all containers and cleans up orphaned containers from removed domains.
# =============================================================================

# =============================================================================
# PHASE 1: Load Environment Variables
# =============================================================================
# Load variables to avoid Docker warnings during the down process.

set -a
source .env
set +a

set -e  # Exit on any error

# =============================================================================
# TERMINAL RESTORATION
# =============================================================================
# Ensures the cursor is restored and echo is enabled if the script is interrupted.

cleanup() {
    tput cnorm  # Restore cursor
    stty echo   # Ensure echo is back
}

trap cleanup EXIT INT TERM

# =============================================================================
# PHASE 2: Build Compose File List
# =============================================================================
# Must match the same files used in start.sh to ensure all containers are stopped.

COMPOSE_FILES="-f docker-compose-traefik-crowdsec-redis.yaml \
               -f docker-compose-tools.yaml \
               -f docker-compose-anubis-generated.yaml \
               -f docker-compose-grafana-loki-alloy.yaml"

# Include Apache host logs for legacy installations (same condition as start.sh)
if [ -d "/var/log/apache2" ]; then
    COMPOSE_FILES="$COMPOSE_FILES -f docker-compose-apache-logs.yaml"
fi

# =============================================================================
# PHASE 3: Stop All Services
# =============================================================================
# --remove-orphans cleans containers for domains that were deleted from the CSV
# and no longer exist in the generated docker-compose files.

echo "🛑 Stopping and cleaning the entire fleet..."
docker compose $COMPOSE_FILES down --remove-orphans

# =============================================================================
# DONE
# =============================================================================

echo ""
echo "✅ Project stopped and clean."
echo ""
