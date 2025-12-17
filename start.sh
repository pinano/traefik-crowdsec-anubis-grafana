#!/bin/bash

# =============================================================================
# start.sh - Stack Deployment Script
# =============================================================================
# Loads configuration, prepares networks, and deploys the stack safely,
# ensuring security components (CrowdSec/Redis) are operational first.
# =============================================================================

set -e  # Exit on any error

# =============================================================================
# PHASE 0: Load Environment Variables
# =============================================================================

set -a
source .env
set +a

# =============================================================================
# PHASE 1: Prepare Anubis Assets
# =============================================================================
# Copy default assets (.dist files) if user hasn't provided custom ones.
# This allows customization while maintaining defaults in version control.

echo "🎨 Checking Anubis assets..."

ANUBIS_ASSETS_DIR="./config/anubis/assets"
ANUBIS_ASSETS_IMG_DIR="$ANUBIS_ASSETS_DIR/static/img"

# Copy default CSS if custom doesn't exist
if [ ! -f "$ANUBIS_ASSETS_DIR/custom.css" ]; then
    if [ -f "$ANUBIS_ASSETS_DIR/custom.css.dist" ]; then
        cp "$ANUBIS_ASSETS_DIR/custom.css.dist" "$ANUBIS_ASSETS_DIR/custom.css"
        echo "   ✅ Copied default custom.css"
    fi
else
    echo "   ℹ️  Using custom custom.css"
fi

# Copy default images if custom versions don't exist
for img in happy.webp pensive.webp reject.webp; do
    if [ ! -f "$ANUBIS_ASSETS_IMG_DIR/$img" ]; then
        if [ -f "$ANUBIS_ASSETS_IMG_DIR/$img.dist" ]; then
            cp "$ANUBIS_ASSETS_IMG_DIR/$img.dist" "$ANUBIS_ASSETS_IMG_DIR/$img"
            echo "   ✅ Copied default $img"
        fi
    else
        echo "   ℹ️  Using custom $img"
    fi
done

# =============================================================================
# PHASE 2: Prepare Traefik Certificate Storage
# =============================================================================
# Create acme.json with restrictive permissions if it doesn't exist.
# This file stores Let's Encrypt certificates and must be chmod 600.

echo "🔐 Checking Traefik certificate storage..."
if [ ! -f ./config/traefik/acme.json ]; then
    touch ./config/traefik/acme.json
    chmod 600 ./config/traefik/acme.json
    echo "   ✅ Created acme.json with secure permissions."
else
    echo "   ✅ acme.json already exists."
fi

# =============================================================================
# PHASE 3: Configure ACME Environment
# =============================================================================
# Priority: ACME_ENV_TYPE > ACME_CA_SERVER (from .env)
# This ensures ACME_ENV_TYPE is respected even if an old ACME_CA_SERVER
# variable remains in the .env file.

echo "🔒 Configuring ACME environment..."
if [ -n "$ACME_ENV_TYPE" ]; then
    case "$ACME_ENV_TYPE" in
        staging)
            export ACME_CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
            echo "   ⚠️  Let's Encrypt STAGING environment."
            ;;
        production)
            export ACME_CA_SERVER="https://acme-v02.api.letsencrypt.org/directory"
            echo "   ✅ Let's Encrypt PRODUCTION environment."
            ;;
        *)
            echo "   ⚠️  Unknown ACME_ENV_TYPE: '$ACME_ENV_TYPE'. Ignoring."
            ;;
    esac
fi

# Default to staging if ACME_CA_SERVER is still empty
if [ -z "$ACME_CA_SERVER" ]; then
    export ACME_CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
    echo "   ⚠️  Let's Encrypt STAGING environment (default)."
elif [ -z "$ACME_ENV_TYPE" ]; then
    # Only show this if using manual override (ACME_ENV_TYPE is empty)
    echo "   🔧 Using custom ACME_CA_SERVER from .env."
fi

# =============================================================================
# PHASE 4: Generate Configuration Files
# =============================================================================

# Generate traefik-generated.yml from template
echo "🔧 Generating traefik-generated.yml from template..."
if [ -f "./config/traefik/traefik.yml.template" ]; then
    sed -e "s|ACME_EMAIL_PLACEHOLDER|${ACME_EMAIL}|g" \
        -e "s|ACME_CASERVER_PLACEHOLDER|${ACME_CA_SERVER}|g" \
        ./config/traefik/traefik.yml.template > ./config/traefik/traefik-generated.yml
    echo "   ✅ traefik-generated.yml generated."
else
    echo "❌ Error: config/traefik/traefik.yml.template not found!"
    exit 1
fi

# Generate dynamic configuration with Python script
echo "🔧 Generating dynamic configuration..."
python3 generate-config.py
echo "   ✅ Dynamic configuration generated."

# =============================================================================
# PHASE 5: Prepare Docker Networks
# =============================================================================
# Create isolated internal network for Anubis backend communication.
# --internal flag ensures no external host traffic can reach this network.

echo "🌐 Checking Docker networks..."
if ! docker network inspect anubis-backend >/dev/null 2>&1; then
    docker network create --internal anubis-backend
    echo "   ✅ Created anubis-backend network (internal)."
else
    echo "   ✅ anubis-backend network already exists."
fi

# =============================================================================
# PHASE 6: Build Compose File List
# =============================================================================

COMPOSE_FILES="-f docker-compose-traefik-crowdsec-redis.yml \
               -f docker-compose-tools.yml \
               -f docker-compose-anubis-generated.yml \
               -f docker-compose-grafana-loki-alloy.yml"

# Include Apache host logs for legacy installations
if [ -d "/var/log/apache2" ]; then
    COMPOSE_FILES="$COMPOSE_FILES -f docker-compose-apache-logs.yml"
    echo "   📋 Apache logs detected, including docker-compose-apache-logs.yml"
fi

# =============================================================================
# PHASE 7: Boot Security Layer First
# =============================================================================
# Start CrowdSec and Redis before other services to ensure the security
# layer is ready when Traefik starts.

echo "🛡️  Booting security layer (CrowdSec + Redis)..."
docker compose $COMPOSE_FILES up -d crowdsec redis

# Wait for CrowdSec to be healthy (smart wait instead of blind sleep)
echo -n "   ⏳ Waiting for CrowdSec API"
timeout=60
while [ "$(docker inspect --format='{{.State.Health.Status}}' crowdsec 2>/dev/null)" != "healthy" ]; do
    sleep 2
    echo -n "."
    ((timeout-=2))
    if [ $timeout -le 0 ]; then
        echo ""
        echo "   ❌ Timeout waiting for CrowdSec to become healthy."
        exit 1
    fi
done
echo " ready!"
echo "   ✅ CrowdSec operational."

# =============================================================================
# PHASE 8: Register Bouncer API Key
# =============================================================================
# Re-register the bouncer key on each start to ensure consistency.
# Delete first (silently) in case it already exists, then add fresh.

echo "👮 Synchronizing Bouncer..."
docker exec crowdsec cscli bouncers delete traefik-bouncer > /dev/null 2>&1 || true
docker exec crowdsec cscli bouncers add traefik-bouncer --key "${CROWDSEC_API_KEY}" > /dev/null

if [ $? -eq 0 ]; then
    echo "   🔑 Bouncer key registered successfully."
else
    echo "⚠️  Error registering bouncer key. Check CrowdSec logs."
    exit 1
fi

# =============================================================================
# PHASE 9: Deploy Remaining Services
# =============================================================================
# Now that the security layer is ready, deploy everything else.
# --remove-orphans cleans up any old containers not in current config.

echo "🚀 Deploying Traefik and remaining services..."
docker compose $COMPOSE_FILES up -d --remove-orphans

# =============================================================================
# DONE
# =============================================================================

echo ""
echo "✅ Deployment complete!"
echo ""
