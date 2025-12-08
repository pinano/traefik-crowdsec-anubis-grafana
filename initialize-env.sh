#!/bin/bash

# initialize_env.sh
# Automates the setup of the .env file from .env.dist

set -e

DIST_FILE=".env.dist"
ENV_FILE=".env"

# ASCII Art / Header
echo "========================================================"
echo "      🤖 TRAEFIK + CROWDSEC + ANUBIS SETUP 🤖            "
echo "========================================================"

# 1. File Setup
if [ ! -f "$DIST_FILE" ]; then
    echo "❌ Error: $DIST_FILE not found."
    exit 1
fi

if [ -f "$ENV_FILE" ]; then
    echo "⚠️  $ENV_FILE already exists."
    read -p "   Overwrite it? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "   Aborted."
        exit 0
    fi
    cp "$ENV_FILE" "${ENV_FILE}.save"
    echo "   Backup created at ${ENV_FILE}.save"
fi

echo "📋 Copying $DIST_FILE to $ENV_FILE..."
cp "$DIST_FILE" "$ENV_FILE"

# Helper function to prompt and replace
# usage: prompt_val VAR_NAME DESCRIPTION
prompt_val() {
    local var_name=$1
    local desc=$2
    # Grep the current value from the file (handles defaults from dist)
    local current_val
    current_val=$(grep "^${var_name}=" "$ENV_FILE" | cut -d'=' -f2-)
    
    # Remove single quotes if present for display
    local display_val="${current_val//\'/}"

    echo ""
    echo "👉 $desc"
    read -p "   Enter value [${display_val}]: " input_val

    if [ -n "$input_val" ]; then
        # Escape special characters for sed (basic)
        local escaped_val=$(echo "$input_val" | sed -e 's/[]\/$*.^[]/\\&/g')
        # Use a generic separator | to avoid path issues
        if [[ "$OSTYPE" == "darwin"* ]]; then
             sed -i '' "s|^${var_name}=.*|${var_name}=${input_val}|" "$ENV_FILE"
        else
             sed -i "s|^${var_name}=.*|${var_name}=${input_val}|" "$ENV_FILE"
        fi
        echo "   ✅ Set to: $input_val"
    else
        echo "   ⏭️ Keeping default: $display_val"
    fi
}

# Helper to blindly replace without prompt
replace_val() {
    local var_name=$1
    local new_val=$2
    if [[ "$OSTYPE" == "darwin"* ]]; then
         sed -i '' "s|^${var_name}=.*|${var_name}=${new_val}|" "$ENV_FILE"
    else
         sed -i "s|^${var_name}=.*|${var_name}=${new_val}|" "$ENV_FILE"
    fi
}

echo ""
echo "🔧 CONFIGURING VARIABLES..."

# --- INTERACTIVE PROMPTS ---

prompt_val "DOMAIN" "Core domain (e.g. example.com)"
prompt_val "TZ" "Timezone (e.g. Europe/Madrid)"
prompt_val "ACME_EMAIL" "Let's Encrypt email"

prompt_val "ANUBIS_DIFFICULTY" "Anubis challenge difficulty (1-5)"
prompt_val "ANUBIS_LOGO_URL" "URL for custom Anubis logo"
prompt_val "ANUBIS_CPU_LIMIT" "Anubis CPU limit per instance"
prompt_val "ANUBIS_MEM_LIMIT" "Anubis memory limit per instance"

# REDIS_PASSWORD: Offer random generation
echo ""
read -p "👉 Generate random REDIS_PASSWORD (20 chars)? (Y/n): " gen_redis
if [[ "$gen_redis" == "y" || "$gen_redis" == "Y" || -z "$gen_redis" ]]; then
    # Generate 20 chars, alphanumeric
    NEW_REDIS_PASS=$(openssl rand -base64 20 | tr -dc 'a-zA-Z0-9' | head -c 20)
    replace_val "REDIS_PASSWORD" "$NEW_REDIS_PASS"
    echo "   ✅ Generated REDIS_PASSWORD: $NEW_REDIS_PASS"
else
    prompt_val "REDIS_PASSWORD" "Redis Password (manual input)"
fi

prompt_val "CROWDSEC_UPDATE_INTERVAL" "CrowdSec update interval (seconds)"

prompt_val "GLOBAL_RATE_AVG" "Traefik default rate limit (requests/sec)"
prompt_val "GLOBAL_RATE_BURST" "Traefik default burst limit"
prompt_val "GLOBAL_CONCURRENCY" "Traefik global concurrency"
prompt_val "HSTS_MAX_AGE" "HSTS max age (seconds)"

# --- AUTOMATED GENERATION ---

echo ""
echo "🔐 GENERATING SECURITY KEYS..."

# 1. ANUBIS_REDIS_PRIVATE_KEY
read -p "👉 Generate new Anubis Redis private key with openssl? (Y/n): " gen_anubis
if [[ "$gen_anubis" == "y" || "$gen_anubis" == "Y" || -z "$gen_anubis" ]]; then
    NEW_KEY=$(openssl rand -hex 32)
    replace_val "ANUBIS_REDIS_PRIVATE_KEY" "$NEW_KEY"
    echo "   ✅ Generated ANUBIS_REDIS_PRIVATE_KEY"
fi

# 2. ADMINISTRATIVE CREDENTIALS (Grafana + Traefik/Dozzle)
echo ""
read -p "👉 Configure unified Admin Credentials (Grafana + Traefik/Dozzle)? (Y/n): " gen_auth
if [[ "$gen_auth" == "y" || "$gen_auth" == "Y" || -z "$gen_auth" ]]; then
    printf "   Username: "
    read -r admin_user
    printf "   Password: "
    read -r -s admin_pass
    echo ""
    echo ""

    # Action 1: Update Grafana (Plaintext)
    replace_val "GF_ADMIN_USER" "$admin_user"
    replace_val "GF_ADMIN_PASSWORD" "$admin_pass"
    echo "   ✅ Updated Grafana credentials"

    # Action 2: Update Traefik/Dozzle (Hashed)
    echo "   ⏳ Hashing compatible with htpasswd..."
    # Run docker to generate hash consistently
    HASH=$(docker run --rm httpd:alpine htpasswd -Bbn "$admin_user" "$admin_pass")
    # Wrap in single quotes to handle special chars in hash
    replace_val "TRAEFIK_DASHBOARD_AUTH" "'$HASH'"
    echo "   ✅ Updated TRAEFIK_DASHBOARD_AUTH hash"
fi

# 3. CROWDSEC_API_KEY
echo ""
read -p "👉 Generate NEW CrowdSec API Key (requires starting docker)? (y/N): " gen_cs
if [[ "$gen_cs" == "y" || "$gen_cs" == "Y" ]]; then
    # Ensure network exists
    if ! docker network inspect traefik >/dev/null 2>&1; then
        echo "   🌐 Creating required 'traefik' network..."
        docker network create traefik
    fi

    echo "   🚀 Starting CrowdSec container..."
    docker compose -f docker-compose-traefik-crowdsec-redis.yml up -d crowdsec
    
    echo "   ⏳ Waiting for CrowdSec API..."
    # Wait loop
    timeout=60
    while [ "$(docker inspect --format='{{.State.Health.Status}}' crowdsec 2>/dev/null)" != "healthy" ]; do
        sleep 2
        echo -n "."
        ((timeout-=2))
        if [ $timeout -le 0 ]; then
             echo "   ❌ Timeout waiting for CrowdSec."
             break
        fi
    done
    echo ""

    if [ "$(docker inspect --format='{{.State.Health.Status}}' crowdsec 2>/dev/null)" == "healthy" ]; then
        echo "   🔑 Generating CROWDSEC_API_KEY..."
        # First remove old one if exists to avoid error
        docker exec crowdsec cscli bouncers delete traefik-bouncer >/dev/null 2>&1 || true
        # Add new one and capture output
        CS_KEY=$(docker exec crowdsec cscli bouncers add traefik-bouncer -o raw)
        
        if [ -n "$CS_KEY" ]; then
            replace_val "CROWDSEC_API_KEY" "$CS_KEY"
            echo "   ✅ Generated and saved CROWDSEC_API_KEY"
        else
            echo "   ❌ Failed to retrieve key from cscli."
        fi
    fi

    echo "   🛑 Stopping CrowdSec..."
    docker compose -f docker-compose-traefik-crowdsec-redis.yml stop crowdsec
fi

echo ""
echo "========================================================"
echo "✅ SETUP COMPLETE! settings saved to $ENV_FILE"
echo "========================================================"
