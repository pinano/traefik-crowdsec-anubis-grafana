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
# Try to load .env if it exists
[ -f .env ] && source .env
set +a

# Default values for critical variables to avoid docker-compose warnings
export TRAEFIK_CONFIG_HASH=${TRAEFIK_CONFIG_HASH:-""}
export DOMAIN_MANAGER_PROJECT_NAME=${DOMAIN_MANAGER_PROJECT_NAME:-"stack"}

set -e  # Exit on any error

# =============================================================================
# TERMINAL RESTORATION
# =============================================================================
# Ensures the cursor is restored and echo is enabled if the script is interrupted.

cleanup() {
    if [ -t 0 ]; then
        tput cnorm  # Restore cursor
        stty echo   # Ensure echo is back
    fi
}

trap cleanup EXIT INT TERM

# =============================================================================
# PHASE 2: Build Compose File List
# =============================================================================
# Must match the same files used in start.sh to ensure all containers are stopped.

COMPOSE_FILES="-f docker-compose-traefik-crowdsec-redis.yaml \
               -f docker-compose-tools.yaml \
               -f docker-compose-anubis-generated.yaml \
               -f docker-compose-grafana-loki-alloy.yaml \
               -f docker-compose-domain-manager.yaml"

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

# Enforce project name to avoid missing containers
COMPOSE_CMD="docker compose -p $DOMAIN_MANAGER_PROJECT_NAME --profile crowdsec"

# 1. Graceful stop (allow containers to finish tasks)
# We use || true to ensure 'down' runs even if 'stop' encounters issues
echo "   ➜ Stopping services gracefully (20s timeout)..."
$COMPOSE_CMD $COMPOSE_FILES stop -t 20 || true

# 2. Complete removal
echo "   ➜ Removing containers and cleaning orphans..."
$COMPOSE_CMD $COMPOSE_FILES down --remove-orphans

# =============================================================================
# DONE
# =============================================================================

echo ""
echo "✅ Project stopped and clean."
echo ""
