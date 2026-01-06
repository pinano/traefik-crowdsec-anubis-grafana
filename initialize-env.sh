#!/bin/bash

# initialize_env.sh
# Automates the setup of the .env file from .env.dist

set -e

# =============================================================================
# TERMINAL RESTORATION
# =============================================================================

cleanup() {
    tput cnorm  # Restore cursor
    stty echo   # Ensure echo is back
}

trap cleanup EXIT INT TERM

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
prompt_val "TRAEFIK_LISTEN_IP" "Traefik Listen IP (default: 0.0.0.0 for all)"
prompt_val "ACME_ENV_TYPE" "ACME Environment (production/staging)"

prompt_val "ANUBIS_DIFFICULTY" "Anubis challenge difficulty (1-5)"
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

echo ""
read -p "👉 Disable CrowdSec Firewall completely? (y/N): " disable_cs
if [[ "$disable_cs" == "y" || "$disable_cs" == "Y" ]]; then
    replace_val "DISABLE_CROWDSEC" "true"
    echo "   ✅ CrowdSec DISABLED"
else
    replace_val "DISABLE_CROWDSEC" "false"
    echo "   ✅ CrowdSec ENABLED"
fi

echo ""
echo "👉 CrowdSec Console Enrollment (optional)"
echo "   Get your key from https://app.crowdsec.net"
read -p "   Enter enrollment key (leave empty to skip): " cs_enroll_key
if [ -n "$cs_enroll_key" ]; then
    replace_val "CROWDSEC_ENROLLMENT_KEY" "$cs_enroll_key"
    echo "   ✅ Set CROWDSEC_ENROLLMENT_KEY"
else
    echo "   ⏭️ Skipping console enrollment"
fi

echo ""
echo "👉 CrowdSec Collections (scenarios/parsers)"
echo "   Remove 'crowdsecurity/http-dos' if you get too many false positives"
echo "   ⚠️  If you modify this on an existing installation, you may need to reset CrowdSec volumes:"
echo "      docker volume rm \$(docker volume ls -q | grep crowdsec)"
prompt_val "CROWDSEC_COLLECTIONS" "CrowdSec collections to load (space-separated)"

echo ""
echo "👉 CrowdSec IP Whitelist (optional)"
echo "   Enter IPs/CIDRs to bypass CrowdSec detection (comma-separated)"
echo "   Example: 192.168.1.1,10.0.0.0/8"
prompt_val "CROWDSEC_WHITELIST_IPS" "CrowdSec whitelist IPs (leave empty for none)"

prompt_val "GLOBAL_RATE_AVG" "Traefik default rate limit (requests/sec)"
prompt_val "GLOBAL_RATE_BURST" "Traefik default burst limit"
prompt_val "GLOBAL_CONCURRENCY" "Traefik global concurrency"
prompt_val "TRAEFIK_TIMEOUT_ACTIVE" "Traefik active timeout (read/write/header) in seconds"
prompt_val "TRAEFIK_TIMEOUT_IDLE" "Traefik idle timeout in seconds"
prompt_val "HSTS_MAX_AGE" "HSTS max age (seconds)"

prompt_val "GF_ADMIN_USER" "Admin User (Grafana, Traefik, Dozzle)"
prompt_val "GF_ADMIN_PASSWORD" "Admin Password (Grafana, Traefik, Dozzle)"

prompt_val "TELEGRAM_BOT_TOKEN" "Telegram Bot Token (for Let's Encrypt renewal alerts)"
prompt_val "TELEGRAM_RECIPIENT_ID" "Telegram Chat/Group ID (for Let's Encrypt renewal alerts)"
prompt_val "DAYS_WARNING" "Days before SSL certificateexpiration to send alert (default: 10)"

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

# 2. TRAEFIK/DOZZLE DASHBOARD AUTH (Auto-generated from above)
echo ""
echo "� Generating Traefik/Dozzle Auth Hash from Admin credentials..."
# Read values directly from the .env file (handled by prompt_val earlier)
ADM_USER=$(grep "^GF_ADMIN_USER=" "$ENV_FILE" | cut -d'=' -f2-)
ADM_PASS=$(grep "^GF_ADMIN_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2-)

if [ -n "$ADM_USER" ] && [ -n "$ADM_PASS" ]; then
    echo "   ⏳ Hashing compatible with htpasswd..."
    # Run docker to generate hash consistently
    HASH=$(docker run --rm httpd:alpine htpasswd -Bbn "$ADM_USER" "$ADM_PASS")
    # Wrap in single quotes to handle special chars in hash
    replace_val "TRAEFIK_DASHBOARD_AUTH" "'$HASH'"
    echo "   ✅ Updated TRAEFIK_DASHBOARD_AUTH hash"
else
    echo "   ⚠️  Skipping hash generation: GF_ADMIN_USER or GF_ADMIN_PASSWORD not set."
fi

# 3. CROWDSEC_API_KEY
DISABLE_CS=$(grep "^DISABLE_CROWDSEC=" "$ENV_FILE" | cut -d'=' -f2-)
if [[ "$DISABLE_CS" != "true" ]]; then
    echo ""
    read -p "👉 Generate NEW CrowdSec API Key (requires starting docker)? (y/N): " gen_cs
    if [[ "$gen_cs" == "y" || "$gen_cs" == "Y" ]]; then
    # Ensure network exists
    if ! docker network inspect traefik >/dev/null 2>&1; then
        echo "   🌐 Creating required 'traefik' network..."
        docker network create traefik
    fi

    echo "   🚀 Starting CrowdSec container..."
    docker compose -f docker-compose-traefik-crowdsec-redis.yaml up -d crowdsec
    
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
    docker compose -f docker-compose-traefik-crowdsec-redis.yaml stop crowdsec
    fi
else
    echo ""
    echo "   ⏭️ Skipping CrowdSec API Key generation (CrowdSec is disabled)."
fi

echo ""
echo "========================================================"
echo "✅ SETUP COMPLETE! settings saved to $ENV_FILE"
echo "========================================================"
