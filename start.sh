#!/bin/bash

# start.sh
# Loads configuration, prepares networks, and deploys the stack safely,
# ensuring security components (CrowdSec/Redis) are operational first.

# Load variables from .env by automatically exporting them
set -a
source .env
set +a

# If Traefik's acme.json doesn't exist, create it empty first
if [ ! -f ./config-traefik/acme.json ]; then
    touch ./config-traefik/acme.json
    # Set restrictive permissions (rw for owner, nothing for others)
    chmod 600 ./config-traefik/acme.json
fi

# Logic to set ACME_CA_SERVER based on ACME_ENV_TYPE
# PRIORITY: ACME_ENV_TYPE > ACME_CA_SERVER (from .env)
# This ensures that if the user sets ACME_ENV_TYPE, it is respected, 
# even if an old ACME_CA_SERVER variable remains in the .env file.

if [ -n "$ACME_ENV_TYPE" ]; then
    if [ "$ACME_ENV_TYPE" = "staging" ]; then
        export ACME_CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
        echo "⚠️  Traefik configured for Let's Encrypt STAGING environment (via ACME_ENV_TYPE)."
    elif [ "$ACME_ENV_TYPE" = "production" ]; then
        export ACME_CA_SERVER="https://acme-v02.api.letsencrypt.org/directory"
        echo "🔒 Traefik configured for Let's Encrypt PRODUCTION environment (via ACME_ENV_TYPE)."
    else
        # If set but unknown value, fall back to what might be in ACME_CA_SERVER or default
        echo "⚠️  Unknown ACME_ENV_TYPE: '$ACME_ENV_TYPE'. Ignoring."
    fi
fi

# If ACME_CA_SERVER is still empty (ACME_ENV_TYPE was not set or invalid, and no ACME_CA_SERVER in .env),
# default to Staging.
if [ -z "$ACME_CA_SERVER" ]; then
     export ACME_CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
     echo "⚠️ Traefik configured for Let's Encrypt STAGING environment (Default)."
elif [ -z "$ACME_ENV_TYPE" ]; then
     # Only show this message if we are using the manual override (ACME_ENV_TYPE is empty)
     echo "🔧 Using custom ACME_CA_SERVER from .env: $ACME_CA_SERVER"
fi

# Generate traefik-generated.yml from template
echo "🔧 Generating traefik-generated.yml from template..."
if [ -f "./config-traefik/traefik.yml.template" ]; then
    sed -e "s|ACME_EMAIL_PLACEHOLDER|${ACME_EMAIL}|g" \
        -e "s|ACME_CASERVER_PLACEHOLDER|${ACME_CA_SERVER}|g" \
        ./config-traefik/traefik.yml.template > ./config-traefik/traefik-generated.yml
    echo "✅ traefik-generated.yml generated successfully."
else
    echo "❌ Error: config-traefik/traefik.yml.template not found!"
    exit 1
fi

echo "🔧 Generating dynamic configuration with python script..."
python3 generate-config.py
echo "✅ Configuration generated."

# 0. NETWORK PREPARATION
echo "🌐 Checking for isolated network 'anubis-backend'..."

# Use 'inspect' instead of 'ls' to ensure EXACT match
if ! docker network inspect anubis-backend >/dev/null 2>&1; then
    echo "    Creating anubis-backend network (internal)..."
    # --internal ensures no external host traffic can reach this network
    docker network create --internal anubis-backend
else
    echo "   Network already exists correctly."
fi

# Define the compose files to avoid repeating the list and potential errors
COMPOSE_FILES="-f docker-compose-traefik-crowdsec-redis.yml \
               -f docker-compose-dozzle-ctop.yml \
               -f docker-compose-anubis-generated.yml \
               -f docker-compose-grafana-loki-alloy.yml"

# 1. SECURE BOOT PHASE: CrowdSec + Redis
echo "🛡️ Booting up security layer (CrowdSec)..."
# Start only the security/persistence services first
docker compose $COMPOSE_FILES up -d crowdsec redis

# 2. SMART WAIT (Health Check)
# Instead of sleeping blindly, we check Docker's health status for CrowdSec
echo "⏳ Waiting for CrowdSec API to be ready..."
timeout=60
while [ "$(docker inspect --format='{{.State.Health.Status}}' crowdsec 2>/dev/null)" != "healthy" ]; do
    sleep 2
    echo -n "."
    ((timeout-=2))
    if [ $timeout -le 0 ]; then
        echo "❌ Timeout waiting for CrowdSec."
        exit 1
    fi
done
echo "✅ CrowdSec operational."

# 3. IDENTITY MANAGEMENT (Now it's 100% safe to do it)
echo "👮 Synchronizing Bouncer..."
# Silently delete the bouncer in case it already exists
docker exec crowdsec cscli bouncers delete traefik-bouncer > /dev/null 2>&1 || true
# Add the key (which Traefik will use later) using the environment variable
docker exec crowdsec cscli bouncers add traefik-bouncer --key "${CROWDSEC_API_KEY}" > /dev/null

if [ $? -eq 0 ]; then
    echo "🔑 Key successfully registered."
else
    # Changed error message to be more explicit
    echo "⚠️ Error registering key. Check CrowdSec logs."
    exit 1
fi

# 4. MAIN FLEET DEPLOYMENT
# Now that the Key exists, Traefik can start and connect immediately
echo "🚀 Deploying Traefik and remaining services..."
# --remove-orphans ensures any old, unmanaged containers are removed.
docker compose $COMPOSE_FILES up -d --remove-orphans

echo "✅ Deployment finished with no race conditions."
