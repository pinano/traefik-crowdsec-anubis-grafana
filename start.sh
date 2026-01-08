#!/bin/bash

# =============================================================================
# start.sh - Stack Deployment Script
# =============================================================================
# Loads configuration, prepares networks, and deploys the stack safely,
# ensuring security components (CrowdSec/Redis) are operational first.
# =============================================================================

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

# Ensures .env exists and is up to date with .env.dist structure.

DIST_FILE=".env.dist"
ENV_FILE=".env"

# 1. Check if .env exists, if not, initialize
if [ ! -f "$ENV_FILE" ]; then
    echo "⚠️  $ENV_FILE not found. Running initialization..."
    if [ -f "./initialize-env.sh" ]; then
        chmod +x ./initialize-env.sh
        ./initialize-env.sh
        exit 0
    else
        echo "❌ Error: initialize-env.sh not found. Please create $ENV_FILE manually."
        exit 1
    fi
fi

# 2. Sync variables from .env.dist to .env, preserving order
echo "🔄 Synchronizing $ENV_FILE with $DIST_FILE..."
TEMP_ENV=$(mktemp)
ADDED_VARS=0
cp "$ENV_FILE" "${ENV_FILE}.bak"

# Process all lines from .env.dist to maintain its structure
while IFS= read -r line || [ -n "$line" ]; do
    # Preserve comments and empty lines
    if [[ "$line" =~ ^# ]] || [[ -z "$line" ]]; then
        echo "$line" >> "$TEMP_ENV"
        continue
    fi

    # Extract variable name (part before =)
    VAR_NAME=$(echo "$line" | cut -d'=' -f1)
    
    # Check if variable exists in current .env
    if grep -q "^${VAR_NAME}=" "$ENV_FILE"; then
        # Use existing value from .env (take the first occurrence)
        grep "^${VAR_NAME}=" "$ENV_FILE" | head -n 1 >> "$TEMP_ENV"
    else
        # Use default value from .env.dist
        echo "$line" >> "$TEMP_ENV"
        echo "   ➕ Added variable: $VAR_NAME"
        ADDED_VARS=$((ADDED_VARS + 1))
    fi
done < "$DIST_FILE"

# Append any custom variables from .env that are NOT in .env.dist
EXTRA_VARS=0
while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^# ]] || [[ -z "$line" ]]; then continue; fi
    VAR_NAME=$(echo "$line" | cut -d'=' -f1)
    if ! grep -q "^${VAR_NAME}=" "$DIST_FILE"; then
        if [ $EXTRA_VARS -eq 0 ]; then
            echo "" >> "$TEMP_ENV"
            echo "# --- Custom variables (not in .env.dist) ---" >> "$TEMP_ENV"
        fi
        echo "$line" >> "$TEMP_ENV"
        EXTRA_VARS=$((EXTRA_VARS + 1))
    fi
done < "$ENV_FILE"

cat "$TEMP_ENV" > "$ENV_FILE"
rm "$TEMP_ENV"

if [ $ADDED_VARS -gt 0 ]; then
    echo "   ✅ Added $ADDED_VARS new variables from .env.dist."
fi
if [ $EXTRA_VARS -gt 0 ]; then
    echo "   ℹ️  Preserved $EXTRA_VARS custom variables."
fi

# Load variables
set -a
source .env
set +a

# =============================================================================
# PHASE 0: Synchronize Dashboard Hashes
# =============================================================================
# Checks if admin credentials have changed manually in .env and updates hashes.

echo "🔐 Checking admin credentials sync..."

SYNC_NEEDED=0

# Helper to update a variable in .env
update_env_var() {
    local var_name=$1
    local new_val=$2
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|^${var_name}=.*|${var_name}=${new_val}|" .env
    else
        sed -i "s|^${var_name}=.*|${var_name}=${new_val}|" .env
    fi
}

# 1. Traefik Credentials Sync
CURRENT_TRAEFIK_SYNC=$(echo -n "${TRAEFIK_ADMIN_USER}:${TRAEFIK_ADMIN_PASSWORD}" | sha1sum | cut -d' ' -f1)
if [ "$CURRENT_TRAEFIK_SYNC" != "$TRAEFIK_ADMIN_CREDS_SYNC" ]; then
    echo "   🔄 Traefik credentials changed. Regenerating hash..."
    T_HASH=$(docker run --rm httpd:alpine htpasswd -Bbn "$TRAEFIK_ADMIN_USER" "$TRAEFIK_ADMIN_PASSWORD")
    update_env_var "TRAEFIK_DASHBOARD_AUTH" "'$T_HASH'"
    update_env_var "TRAEFIK_ADMIN_CREDS_SYNC" "$CURRENT_TRAEFIK_SYNC"
    export TRAEFIK_DASHBOARD_AUTH="$T_HASH"
    SYNC_NEEDED=$((SYNC_NEEDED + 1))
fi

# 2. Dozzle Credentials Sync
CURRENT_DOZZLE_SYNC=$(echo -n "${DOZZLE_ADMIN_USER}:${DOZZLE_ADMIN_PASSWORD}" | sha1sum | cut -d' ' -f1)
if [ "$CURRENT_DOZZLE_SYNC" != "$DOZZLE_ADMIN_CREDS_SYNC" ]; then
    echo "   🔄 Dozzle credentials changed. Regenerating hash..."
    D_HASH=$(docker run --rm httpd:alpine htpasswd -Bbn "$DOZZLE_ADMIN_USER" "$DOZZLE_ADMIN_PASSWORD")
    update_env_var "DOZZLE_DASHBOARD_AUTH" "'$D_HASH'"
    update_env_var "DOZZLE_ADMIN_CREDS_SYNC" "$CURRENT_DOZZLE_SYNC"
    export DOZZLE_DASHBOARD_AUTH="$D_HASH"
    SYNC_NEEDED=$((SYNC_NEEDED + 1))
fi

if [ $SYNC_NEEDED -gt 0 ]; then
    echo "   ✅ Authentication hashes synchronized in .env. Re-loading environment..."
    set -a
    source .env
    set +a
else
    echo "   ✅ Admin credentials are in sync."
fi

# Normalize CROWDSEC_DISABLE to lowercase
CROWDSEC_DISABLE=$(echo "${CROWDSEC_DISABLE:-false}" | tr '[:upper:]' '[:lower:]')

# Build Compose command with or without CrowdSec profile
# Enforce project name to avoid conflicts when running from within a container
COMPOSE_BASE="docker compose"
if [ -n "$COMPOSE_PROJECT_NAME" ]; then
    COMPOSE_BASE="docker compose -p $COMPOSE_PROJECT_NAME"
fi

COMPOSE_CMD="$COMPOSE_BASE"
if [[ "$CROWDSEC_DISABLE" != "true" ]]; then
    COMPOSE_CMD="$COMPOSE_BASE --profile crowdsec"
    echo "🛡️  CrowdSec firewall is ENABLED."
else
    echo "⚠️  CrowdSec firewall is DISABLED."
fi

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
    echo "   ℹ️ Using custom custom.css"
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
# Priority: TRAEFIK_ACME_ENV_TYPE > TRAEFIK_ACME_CA_SERVER (from .env)
# This ensures TRAEFIK_ACME_ENV_TYPE is respected even if an old TRAEFIK_ACME_CA_SERVER
# variable remains in the .env file.

echo "🔒 Configuring ACME environment..."
if [ -n "$TRAEFIK_ACME_ENV_TYPE" ]; then
    case "$TRAEFIK_ACME_ENV_TYPE" in
        staging)
            export TRAEFIK_ACME_CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
            echo "   ⚠️ Let's Encrypt STAGING environment."
            ;;
        production)
            export TRAEFIK_ACME_CA_SERVER="https://acme-v02.api.letsencrypt.org/directory"
            echo "   ✅ Let's Encrypt PRODUCTION environment."
            ;;
        *)
            echo "   ⚠️ Unknown TRAEFIK_ACME_ENV_TYPE: '$TRAEFIK_ACME_ENV_TYPE'. Ignoring."
            ;;
    esac
fi

# Default to staging if TRAEFIK_ACME_CA_SERVER is still empty
if [ -z "$TRAEFIK_ACME_CA_SERVER" ]; then
    export TRAEFIK_ACME_CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
    echo "   ⚠️ Let's Encrypt STAGING environment (default)."
elif [ -z "$TRAEFIK_ACME_ENV_TYPE" ]; then
    # Only show this if using manual override (TRAEFIK_ACME_ENV_TYPE is empty)
    echo "   🔧 Using custom TRAEFIK_ACME_CA_SERVER from .env."
fi

# =============================================================================
# PHASE 4: Generate Configuration Files
# =============================================================================

# Generate traefik-generated.yaml from template
echo "🔧 Generating traefik-generated.yaml from template..."
if [ -f "./config/traefik/traefik.yaml.template" ]; then
    sed -e "s|TRAEFIK_ACME_EMAIL_PLACEHOLDER|${TRAEFIK_ACME_EMAIL}|g" \
        -e "s|TRAEFIK_ACME_CASERVER_PLACEHOLDER|${TRAEFIK_ACME_CA_SERVER}|g" \
        -e "s|TRAEFIK_TIMEOUT_ACTIVE_PLACEHOLDER|${TRAEFIK_TIMEOUT_ACTIVE:-60}s|g" \
        -e "s|TRAEFIK_TIMEOUT_IDLE_PLACEHOLDER|${TRAEFIK_TIMEOUT_IDLE:-90}s|g" \
        ./config/traefik/traefik.yaml.template > ./config/traefik/traefik-generated.yaml
    echo "   ✅ traefik-generated.yaml produced."
else
    echo "❌ Error: config/traefik/traefik.yaml.template not found!"
    exit 1
fi

# Calculate hash of the generated config to force restart on changes
# relying on Docker Compose to detect env var changes
if [ -f "./config/traefik/traefik-generated.yaml" ]; then
    TRAEFIK_CONFIG_HASH=$(python3 -c "import hashlib; print(hashlib.sha1(open('./config/traefik/traefik-generated.yaml', 'rb').read()).hexdigest())")
    export TRAEFIK_CONFIG_HASH
    echo "   #️⃣  Traefik Config Hash: $TRAEFIK_CONFIG_HASH"
fi

# Generate dynamic configuration with Python script
echo "🔧 Generating dynamic configuration..."
python3 generate-config.py
echo "   ✅ Dynamic configuration generated."

# =============================================================================
# PHASE 4B: Generate CrowdSec IP Whitelist
# =============================================================================
# If CROWDSEC_WHITELIST_IPS is set, generate the whitelist YAML file.
# This file is mounted into CrowdSec and whitelisted IPs bypass all detection.

echo "🛡️  Checking CrowdSec IP whitelist..."
WHITELIST_FILE="./config/crowdsec/parsers/ip-whitelist.yaml"

if [[ "$CROWDSEC_DISABLE" != "true" ]] && [ -n "$CROWDSEC_WHITELIST_IPS" ]; then
    echo "   📋 Generating whitelist from CROWDSEC_WHITELIST_IPS..."
    
    # Build the YAML whitelist file
    cat > "$WHITELIST_FILE" << 'EOF'
# ============================================================================
# CrowdSec IP Whitelist - Auto-generated from CROWDSEC_WHITELIST_IPS
# ============================================================================
# Do not edit this file directly. Modify CROWDSEC_WHITELIST_IPS in .env
# and restart the stack with ./start.sh
# ============================================================================

name: custom/ip-whitelist
description: "User-defined trusted IPs from environment variable"
whitelist:
  reason: "Trusted IP configured via CROWDSEC_WHITELIST_IPS"
  ip:
EOF
    
    # Parse comma-separated IPs and add each as a YAML list item
    IP_COUNT=0
    IFS=',' read -ra IPS <<< "$CROWDSEC_WHITELIST_IPS"
    for ip in "${IPS[@]}"; do
        # Trim whitespace
        ip=$(echo "$ip" | xargs)
        if [ -n "$ip" ]; then
            echo "    - \"$ip\"" >> "$WHITELIST_FILE"
            echo "   ✅ Whitelisted: $ip"
            IP_COUNT=$((IP_COUNT + 1))
        fi
    done
    
    echo "   ✅ Whitelist generated with $IP_COUNT entries."
else
    echo "   ℹ️  No whitelist IPs configured (CROWDSEC_WHITELIST_IPS is empty)."
    # Remove old whitelist if it exists to avoid stale entries
    if [ -f "$WHITELIST_FILE" ]; then
        rm -f "$WHITELIST_FILE"
        echo "   🗑️  Removed old whitelist file."
    fi
fi

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

COMPOSE_FILES="-f docker-compose-traefik-crowdsec-redis.yaml \
               -f docker-compose-tools.yaml \
               -f docker-compose-anubis-generated.yaml \
               -f docker-compose-grafana-loki-alloy.yaml \
               -f docker-compose-domain-manager.yaml"

# Include Apache host logs for legacy installations
if [ -d "/var/log/apache2" ]; then
    COMPOSE_FILES="$COMPOSE_FILES -f docker-compose-apache-logs.yaml"
    echo "   📋 Apache logs detected, including docker-compose-apache-logs.yaml"
fi

# =============================================================================
# PHASE 7: Boot Security Layer First
# =============================================================================
# Start CrowdSec and Redis before other services to ensure the security
# layer is ready when Traefik starts.

if [[ "$CROWDSEC_DISABLE" != "true" ]]; then
    echo "🛡️  Booting security layer (CrowdSec + Redis)..."
    $COMPOSE_CMD $COMPOSE_FILES up -d crowdsec redis

    # Wait for CrowdSec to be healthy (smart wait instead of blind sleep)
    echo -n "   ⏳ Waiting for CrowdSec API"
    timeout=60
    CROWDSEC_ID=$(docker ps -aqf "name=crowdsec" | head -n 1)
    while [ "$(docker inspect --format='{{.State.Health.Status}}' $CROWDSEC_ID 2>/dev/null)" != "healthy" ]; do
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
        echo "⚠️ Error registering bouncer key. Check CrowdSec logs."
        exit 1
    fi

    # =============================================================================
    # PHASE 9: CrowdSec Console Enrollment (Optional)
    # =============================================================================
    # If CROWDSEC_ENROLLMENT_KEY is set, enroll this instance with CrowdSec Console
    # for access to community blocklists and centralized management.

    if [ -n "$CROWDSEC_ENROLLMENT_KEY" ]; then
        echo "🌐 Enrolling in CrowdSec Console..."
        if docker exec crowdsec cscli console enroll "$CROWDSEC_ENROLLMENT_KEY" --name "$(hostname)" 2>/dev/null; then
            echo "   ✅ Successfully enrolled in CrowdSec Console."
        else
            echo "   ⚠️ Console enrollment failed or already enrolled. Continuing..."
        fi
    fi
else
    echo "🛡️  Booting Redis (CrowdSec is disabled)..."
    $COMPOSE_CMD $COMPOSE_FILES up -d redis
    echo "   ✅ Redis operational."
fi

# =============================================================================
# PHASE 10: Deploy Remaining Services
# =============================================================================
# Now that the security layer is ready, deploy everything else.
# --remove-orphans cleans up any old containers not in current config.

echo "🚀 Deploying Traefik and remaining services..."
$COMPOSE_CMD $COMPOSE_FILES up -d --remove-orphans

# =============================================================================
# DONE
# =============================================================================

echo ""
echo "✅ Deployment complete!"
echo ""
