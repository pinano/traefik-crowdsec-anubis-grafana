#!/bin/bash

# =============================================================================
# start.sh - Stack Deployment Script
# =============================================================================
# Loads configuration, prepares networks, and deploys the stack safely,
# ensuring security components (CrowdSec/Redis) are operational first.
# =============================================================================

set -e  # Exit on any error

# ⏲️ Start Timer
START_TIME=$(date +%s)

# 0. Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo ""
echo "========================================================"
echo "🚀 DEPLOYMENT STARTING..."
echo "========================================================"
echo ""

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
    if [ -f "./scripts/initialize-env.sh" ]; then
        chmod +x ./scripts/initialize-env.sh
        ./scripts/initialize-env.sh
        exit 0
    else
        echo "❌ Error: initialize-env.sh not found. Please create $ENV_FILE manually."
        exit 1
    fi
fi

# 1. Environment Preparation
echo " --------------------------------------------------------"
echo " [1/6] 📋 Preparing environment..."
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
    echo "   ℹ️ Preserved $EXTRA_VARS custom variables."
fi

# Load variables
set -a
source .env
set +a

# =============================================================================
# VALIDATION: Check for Critical Configuration Errors
# =============================================================================

validate_env() {
    local error_count=0

    # 1. Check DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo "❌ Error: DOMAIN variable cannot be empty."
        ((error_count++))
    fi

    # 2. Check TRAEFIK_ACME_ENV_TYPE
    if [[ ! "$TRAEFIK_ACME_ENV_TYPE" =~ ^(local|staging|production)$ ]]; then
        echo "❌ Error: TRAEFIK_ACME_ENV_TYPE must be 'local', 'staging', or 'production'. Current: '$TRAEFIK_ACME_ENV_TYPE'"
        ((error_count++))
    fi

    # 3. Check ACME Email (only if not local)
    if [ "$TRAEFIK_ACME_ENV_TYPE" != "local" ]; then
        # Check for default or empty email
        if [[ "$TRAEFIK_ACME_EMAIL" == *"email@mydomain.com"* ]] || [[ "$TRAEFIK_ACME_EMAIL" == *"placeholder"* ]] || [ -z "$TRAEFIK_ACME_EMAIL" ]; then
            echo "❌ Error: TRAEFIK_ACME_EMAIL is set to default or empty, but environment is '$TRAEFIK_ACME_ENV_TYPE'."
            echo "   -> Please set a valid email in .env for Let's Encrypt notifications."
            ((error_count++))
        fi
    fi

    # 4. Check CrowdSec API Key (only if enabled)
    # Normalize CROWDSEC_DISABLE for check (it's normalized again later, but we need it now)
    local cs_disable=$(echo "${CROWDSEC_DISABLE:-false}" | tr '[:upper:]' '[:lower:]')
    if [ "$cs_disable" != "true" ]; then
        if [ "$CROWDSEC_API_KEY" == "REPLACE_ME" ] || [ -z "$CROWDSEC_API_KEY" ]; then
            echo "❌ Error: CrowdSec is ENABLED but CROWDSEC_API_KEY is missing or set to default."
            echo "   -> Either disable CrowdSec (CROWDSEC_DISABLE=true) or generate a key."
            ((error_count++))
        fi
    fi

    if [ $error_count -gt 0 ]; then
        echo ""
        echo "🛑 Validation failed with $error_count errors. Please fix your .env file."
        exit 1
    fi
    echo "✅ Environment configuration valid."
}

# Run validation immediately
validate_env | sed 's/^/   /'


echo " --------------------------------------------------------"
echo " [2/6] 🔐 Synchronizing credentials & paths..."

SYNC_NEEDED=0

# Helper to perform common hashing (portability between Linux/macOS)
# Usage: echo -n "string" | generate_hash  OR  cat file | generate_hash
generate_hash() {
    if command -v sha1sum >/dev/null 2>&1; then
        sha1sum | cut -d' ' -f1
    else
        shasum | cut -d' ' -f1
    fi
}

# Helper to update variables in .env efficiently
# Use a temporary file to batch updates if needed
update_env_var() {
    local var_name=$1
    local new_val=$2
    local TMP_ENV=$(mktemp)
    
    # Use '#' as delimiter for safety with paths/hashes
    sed "s#^${var_name}=.*#${var_name}=${new_val}#" "$ENV_FILE" > "$TMP_ENV"
    cat "$TMP_ENV" > "$ENV_FILE"
    rm "$TMP_ENV"
}

# 1. Traefik Credentials Sync
CURRENT_TRAEFIK_SYNC=$(echo -n "${TRAEFIK_ADMIN_USER}:${TRAEFIK_ADMIN_PASSWORD}" | generate_hash)
if [ "$CURRENT_TRAEFIK_SYNC" != "$TRAEFIK_ADMIN_CREDS_SYNC" ]; then
    echo "   🔄 Traefik credentials changed. Regenerating hash..."
    T_HASH=$(docker run --rm httpd:alpine htpasswd -Bbn "$TRAEFIK_ADMIN_USER" "$TRAEFIK_ADMIN_PASSWORD")
    update_env_var "TRAEFIK_DASHBOARD_AUTH" "'$T_HASH'"
    update_env_var "TRAEFIK_ADMIN_CREDS_SYNC" "$CURRENT_TRAEFIK_SYNC"
    export TRAEFIK_DASHBOARD_AUTH="$T_HASH"
    SYNC_NEEDED=$((SYNC_NEEDED + 1))
fi

# 2. Dozzle Credentials Sync
CURRENT_DOZZLE_SYNC=$(echo -n "${DOZZLE_ADMIN_USER}:${DOZZLE_ADMIN_PASSWORD}" | generate_hash)
if [ "$CURRENT_DOZZLE_SYNC" != "$DOZZLE_ADMIN_CREDS_SYNC" ]; then
    echo "   🔄 Dozzle credentials changed. Regenerating hash..."
    D_HASH=$(docker run --rm httpd:alpine htpasswd -Bbn "$DOZZLE_ADMIN_USER" "$DOZZLE_ADMIN_PASSWORD")
    update_env_var "DOZZLE_DASHBOARD_AUTH" "'$D_HASH'"
    update_env_var "DOZZLE_ADMIN_CREDS_SYNC" "$CURRENT_DOZZLE_SYNC"
    export DOZZLE_DASHBOARD_AUTH="$D_HASH"
    SYNC_NEEDED=$((SYNC_NEEDED + 1))
fi

# 3. Domain Manager Secret Key
if [ -z "$DOMAIN_MANAGER_SECRET_KEY" ] || [ "$DOMAIN_MANAGER_SECRET_KEY" == "REPLACE_ME" ]; then
    echo "   🔄 Domain Manager Secret Key is missing or default. Generating secure key..."
    NEW_DM_KEY=$(openssl rand -hex 32)
    update_env_var "DOMAIN_MANAGER_SECRET_KEY" "$NEW_DM_KEY"
    export DOMAIN_MANAGER_SECRET_KEY="$NEW_DM_KEY"
    SYNC_NEEDED=$((SYNC_NEEDED + 1))
fi

if [ $SYNC_NEEDED -gt 0 ]; then
    echo "   ✅ Credentials synchronized."
    set -a
    source .env
    set +a
else
    echo "   ✅ Credentials in sync."
fi

# =============================================================================
# AUTO-CONFIGURATION: Absolute Path Mirroring
# =============================================================================
# Calculate the absolute path of the project on the host and ensure it is set 
# in .env. This is critical for Docker's working_dir and volume mirroring.

# Use realpath if available, otherwise fallback to readlink -f or pwd -P
if command -v realpath >/dev/null 2>&1; then
    DETECTED_PATH=$(realpath .)
elif command -v readlink >/dev/null 2>&1; then
    DETECTED_PATH=$(readlink -f .)
else
    DETECTED_PATH=$(pwd -P)
fi

# Update .env to ensure Docker Compose picks it up correctly even from the file
update_env_var "DOMAIN_MANAGER_APP_PATH_HOST" "$DETECTED_PATH"
export DOMAIN_MANAGER_APP_PATH_HOST="$DETECTED_PATH"
echo "   ✅ Project path: $DETECTED_PATH"

# Normalize CROWDSEC_DISABLE to lowercase
CROWDSEC_DISABLE=$(echo "${CROWDSEC_DISABLE:-false}" | tr '[:upper:]' '[:lower:]')

# Build Compose command with or without CrowdSec profile
# Enforce project name to avoid conflicts when running from within a container
COMPOSE_BASE="docker compose"
if [ -n "$PROJECT_NAME" ]; then
    COMPOSE_BASE="docker compose -p $PROJECT_NAME"
fi

COMPOSE_CMD="$COMPOSE_BASE"
if [[ "$CROWDSEC_DISABLE" != "true" ]]; then
    echo "   🛡️ CrowdSec firewall is ENABLED."
else
    echo "   ⚠️ CrowdSec firewall is DISABLED."
fi


echo " --------------------------------------------------------"
echo " [3/6] 🎨 Preparing application assets..."

ANUBIS_ASSETS_DIR="./config/anubis/assets"
ANUBIS_ASSETS_IMG_DIR="$ANUBIS_ASSETS_DIR/static/img"

CUSTOM_COUNT=0
DEFAULT_COUNT=0

# CSS asset
if [ ! -f "$ANUBIS_ASSETS_DIR/custom.css" ]; then
    if [ -f "$ANUBIS_ASSETS_DIR/custom.css.dist" ]; then
        cp "$ANUBIS_ASSETS_DIR/custom.css.dist" "$ANUBIS_ASSETS_DIR/custom.css"
    fi
    DEFAULT_COUNT=$((DEFAULT_COUNT + 1))
else
    CUSTOM_COUNT=$((CUSTOM_COUNT + 1))
fi

# Image assets
for img in happy.webp pensive.webp reject.webp; do
    if [ ! -f "$ANUBIS_ASSETS_IMG_DIR/$img" ]; then
        if [ -f "$ANUBIS_ASSETS_IMG_DIR/$img.dist" ]; then
            cp "$ANUBIS_ASSETS_IMG_DIR/$img.dist" "$ANUBIS_ASSETS_IMG_DIR/$img"
        fi
        DEFAULT_COUNT=$((DEFAULT_COUNT + 1))
    else
        CUSTOM_COUNT=$((CUSTOM_COUNT + 1))
    fi
done

if [ $DEFAULT_COUNT -eq 0 ]; then
    echo "   ✅ Anubis assets ready ($CUSTOM_COUNT custom)."
elif [ $CUSTOM_COUNT -eq 0 ]; then
    echo "   ✅ Anubis assets ready ($DEFAULT_COUNT default)."
else
    echo "   ✅ Anubis assets ready ($CUSTOM_COUNT custom, $DEFAULT_COUNT default)."
fi

if [ ! -f ./config/traefik/acme.json ]; then
    touch ./config/traefik/acme.json
    chmod 600 ./config/traefik/acme.json
    echo "   ✅ Created acme.json with secure permissions."
fi

# echo "🔒 Configuring ACME environment..."
TRAEFIK_CERT_RESOLVER="le" # Default to 'le'

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
        local)
            export TRAEFIK_ACME_CA_SERVER="" # No CA for local
            TRAEFIK_CERT_RESOLVER=""         # Disable resolver (no 'le')
            echo "   🏠 Local Development environment (Self-Signed Certs)."
            ;;
        *)
            echo "   ⚠️ Unknown TRAEFIK_ACME_ENV_TYPE: '$TRAEFIK_ACME_ENV_TYPE'. Ignoring."
            ;;
    esac
fi

# Default to staging if TRAEFIK_ACME_CA_SERVER is still empty AND we are NOT in local mode
if [ -z "$TRAEFIK_ACME_CA_SERVER" ] && [ "$TRAEFIK_ACME_ENV_TYPE" != "local" ]; then
    export TRAEFIK_ACME_CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
    echo "   ⚠️ Let's Encrypt STAGING environment (default)."
elif [ -z "$TRAEFIK_ACME_ENV_TYPE" ]; then
    # Only show this if using manual override (TRAEFIK_ACME_ENV_TYPE is empty)
    echo "   🔧 Using custom TRAEFIK_ACME_CA_SERVER from .env."
fi

# Export the resolver choice so Docker Compose can use it
export TRAEFIK_CERT_RESOLVER

# Generate traefik-generated.yaml from template
echo "   ⚙️ Generating Traefik static config..."
if [ -f "./config/traefik/traefik.yaml.template" ]; then
    sed -e "s#TRAEFIK_ACME_EMAIL_PLACEHOLDER#${TRAEFIK_ACME_EMAIL}#g" \
        -e "s#TRAEFIK_ACME_CASERVER_PLACEHOLDER#${TRAEFIK_ACME_CA_SERVER}#g" \
        -e "s#TRAEFIK_TIMEOUT_ACTIVE_PLACEHOLDER#${TRAEFIK_TIMEOUT_ACTIVE:-60}s#g" \
        -e "s#TRAEFIK_TIMEOUT_IDLE_PLACEHOLDER#${TRAEFIK_TIMEOUT_IDLE:-90}s#g" \
        -e "s#TRAEFIK_ACCESS_LOG_BUFFER_PLACEHOLDER#${TRAEFIK_ACCESS_LOG_BUFFER:-1000}#g" \
        -e "s#TRAEFIK_LOG_LEVEL_PLACEHOLDER#${TRAEFIK_LOG_LEVEL:-INFO}#g" \
        ./config/traefik/traefik.yaml.template > ./config/traefik/traefik-generated.yaml
else
    echo "❌ Error: config/traefik/traefik.yaml.template not found!"
    exit 1
fi

# Calculate hash of the generated config to force restart on changes
if [ -f "./config/traefik/traefik-generated.yaml" ]; then
    TRAEFIK_CONFIG_HASH=$(cat ./config/traefik/traefik-generated.yaml | generate_hash)
    export TRAEFIK_CONFIG_HASH
fi

# Generate dynamic configuration with Python script
{
    mkdir -p ./config/traefik/dynamic-config
    mkdir -p ./config/anubis
    : > ./config/traefik/dynamic-config/routers-generated.yaml
    : > ./config/anubis/botPolicy-generated.yaml
} || {
    echo "❌ Error: Could not clean up generated files due to permissions."
    echo "   This usually happens if Docker created the directories as root."
    echo "   Please run: sudo chown -R $(id -u):$(id -g) ."
    exit 1
}

# Safety check: if docker-compose-anubis-generated.yaml is a directory (Docker artifact), try to remove it
if [ -d "docker-compose-anubis-generated.yaml" ]; then
    echo "⚠️ Cleaning up directory collision: docker-compose-anubis-generated.yaml"
    rm -rf docker-compose-anubis-generated.yaml || echo "   ⚠️  Warning: Could not remove directory 'docker-compose-anubis-generated.yaml'. If it's a mount point, this is expected."
else
    # Instead of rm, we truncate to avoid "Resource busy" if the file is mounted
    : > docker-compose-anubis-generated.yaml
fi

# Safety check: if domains.csv is a directory (Docker artifact), remove it
if [ -d "domains.csv" ]; then
    echo "⚠️ Cleaning up directory collision: domains.csv"
    rm -rf domains.csv
fi

# Ensure domains.csv exists with correct header
if [ ! -f "domains.csv" ]; then
    echo "   📄 Creating default domains.csv..."
    echo "# domain, redirection, service, anubis_subdomain, rate, burst, concurrency" > domains.csv
fi

# Determine Python interpreter
if [ -f ".venv/bin/python3" ]; then
    PYTHON_CMD=".venv/bin/python3"
elif [ -f "venv/bin/python3" ]; then
    PYTHON_CMD="venv/bin/python3"
else
    PYTHON_CMD="python3"
fi

# Check dependencies before running
if ! $PYTHON_CMD -c "import tldextract; import yaml" >/dev/null 2>&1; then
    echo "❌ Error: Python dependencies missing (tldextract, pyyaml)."
    echo "   👉 Please run 'make init' to set up the environment."
    exit 1
fi

$PYTHON_CMD scripts/generate-config.py | sed 's/^/   /'

# Fix permissions if running internally (files created as root)
if [[ "$DOMAIN_MANAGER_INTERNAL" == "true" ]]; then
    echo "   🔧 Internal run detected. Fixing permissions for generated files..."
    # We try to match the parent directory's ownership if possible, or just ensure readability
    # Ideally we would know the host UID/GID, but making them world-readable (644) for config files is usually safe enough for Traefik to read.
    # config/traefik/dynamic-config is mounted ro in Traefik, but Traefik needs to read it.
    
    # Robust permission fix: Directories 755, Files 644
    find ./config/traefik -type d -exec chmod 755 {} \;
    find ./config/traefik -type f -name "*.yaml" -exec chmod 644 {} \;
    find ./config/traefik -type f -name "*.json" -exec chmod 600 {} \; # acme.json needs 600
    chmod 644 ./domains.csv
    
    # Ensure acme.json is strictly 600 (override the find above if needed, though find catches json)
    # But acme.json should NOT be world readable? Traefik generally wants 600.
    # If find set it to 644 (if ended in yaml?), no. acme.json ends in json.
    # We explicitly force acme.json to 600 just in case.
    if [ -f "./config/traefik/acme.json" ]; then
        chmod 600 ./config/traefik/acme.json
    fi
    
    # If we can, try to chown to the owner of the config dir (which is likely the host user)
    # This might fail if the container doesn't see the host users, but we can try referencing the UID of the folder.
    TARGET_UID=$(stat -c '%u' ./config/traefik)
    TARGET_GID=$(stat -c '%g' ./config/traefik)
    
    if [ -n "$TARGET_UID" ] && [ -n "$TARGET_GID" ]; then
         chown -R "$TARGET_UID:$TARGET_GID" ./config/traefik/dynamic-config
         chown "$TARGET_UID:$TARGET_GID" ./domains.csv
         echo "      ✅ Ownership fixed to $TARGET_UID:$TARGET_GID"
    else
         echo "      ⚠️  Could not determine target ownership. Left as root but readable."
    fi
fi

# =============================================================================
# PHASE 4B: Local SSL Trust (mkcert)
# =============================================================================
# If local certificates are found, configure Traefik to use them as default.

# =============================================================================
# PHASE 4B: Local SSL Trust (mkcert)
# =============================================================================
# If local certificates are found AND we are in local mode, configure Traefik to use them.

if [ "$TRAEFIK_ACME_ENV_TYPE" == "local" ]; then
    echo "   🔐 Local Mode detected. Automating certificate generation..."
    if [ -f "./scripts/create-local-certs.sh" ]; then
        chmod +x ./scripts/create-local-certs.sh
        ./scripts/create-local-certs.sh
    else
        echo "   ⚠️ Warning: ./create-local-certs.sh not found. Skipping auto-generation."
    fi

    echo "   🔐 Checking for local trusted certificates (Local Mode)..."
    CERTS_DIR="./config/traefik/certs-local-dev"
    TRAEFIK_CERTS_CONF="./config/traefik/dynamic-config/local-certs.yaml"

    if [ -f "$CERTS_DIR/local-cert.pem" ] && [ -f "$CERTS_DIR/local-key.pem" ]; then
        echo "   📋 Local certificates found. Configuring Traefik to use them..."
        cat > "$TRAEFIK_CERTS_CONF" << EOF
# AUTOMATICALLY GENERATED - Local SSL Trust
tls:
  stores:
    default:
      defaultCertificate:
        certFile: /certs/local-cert.pem
        keyFile: /certs/local-key.pem
EOF
        echo "   ✅ Generated local-certs.yaml."
    else
        echo "   ℹ️ No custom local certificates found."
        if [ -f "$TRAEFIK_CERTS_CONF" ]; then
            rm "$TRAEFIK_CERTS_CONF"
            echo "   🗑️  Removed stale local-certs.yaml."
        fi
    fi
fi


echo " --------------------------------------------------------"
echo " [4/6] 🌐 Preparing network & security layer..."
WHITELIST_FILE="./config/crowdsec/parsers/ip-whitelist.yaml"

if [[ "$CROWDSEC_DISABLE" != "true" ]]; then
    
    # Initialize lists with default internal ranges
    declare -a IPS_LIST=("127.0.0.1")
    declare -a CIDRS_LIST=("172.16.0.0/12" "10.0.0.0/8" "192.168.0.0/16")
    
    # Add custom entries from .env if present
    CUSTOM_ENTRY_COUNT=0
    if [ -n "$CROWDSEC_WHITELIST_IPS" ]; then
        IFS=',' read -ra ENTRIES <<< "$CROWDSEC_WHITELIST_IPS"
        for entry in "${ENTRIES[@]}"; do
            entry=$(echo "$entry" | xargs) # Trim
            if [ -n "$entry" ]; then
                if [[ "$entry" == *"/"* ]]; then
                    CIDRS_LIST+=("$entry")
                    CUSTOM_ENTRY_COUNT=$((CUSTOM_ENTRY_COUNT + 1))
                else
                    IPS_LIST+=("$entry")
                    CUSTOM_ENTRY_COUNT=$((CUSTOM_ENTRY_COUNT + 1))
                fi
            fi
        done
    fi

    # Build the YAML whitelist file
    cat > "$WHITELIST_FILE" << 'EOF'
# ============================================================================
# CrowdSec IP Whitelist - Auto-generated
# ============================================================================
# This file includes internal network ranges and custom IPs from .env
# ============================================================================

name: custom/ip-whitelist
description: "Internal network ranges and user-defined trusted IPs"
whitelist:
  reason: "Internal network or configured via CROWDSEC_WHITELIST_IPS"
EOF

    # Write IP section
    if [ ${#IPS_LIST[@]} -gt 0 ]; then
        echo "  ip:" >> "$WHITELIST_FILE"
        for ip in "${IPS_LIST[@]}"; do
            echo "    - \"$ip\"" >> "$WHITELIST_FILE"
        done
    fi

    # Write CIDR section
    if [ ${#CIDRS_LIST[@]} -gt 0 ]; then
        echo "  cidr:" >> "$WHITELIST_FILE"
        for cidr in "${CIDRS_LIST[@]}"; do
            echo "    - \"$cidr\"" >> "$WHITELIST_FILE"
        done
    fi
    
    TOTAL_ENTRIES=$((${#IPS_LIST[@]} + ${#CIDRS_LIST[@]}))
    if [ $CUSTOM_ENTRY_COUNT -gt 0 ]; then
        echo "   ✅ CrowdSec whitelist: $TOTAL_ENTRIES entries ($CUSTOM_ENTRY_COUNT custom)."
    else
        echo "   ✅ CrowdSec whitelist: $TOTAL_ENTRIES entries."
    fi
else
    echo "   ℹ️ CrowdSec is disabled, skipping whitelist generation."
    # Remove old whitelist if it exists to avoid stale entries
    if [ -f "$WHITELIST_FILE" ]; then
        rm -f "$WHITELIST_FILE"
        echo "   🗑️ Removed old whitelist file."
    fi
fi

# =============================================================================
# PHASE 4D: User-Agent Blacklist Configuration
# =============================================================================
# This variable is used by generate-config.py to create native Traefik blocking rules.
if [ -n "$TRAEFIK_BAD_USER_AGENTS" ]; then
    UA_COUNT=$(echo "$TRAEFIK_BAD_USER_AGENTS" | tr ',' '\n' | grep -c .)
    echo "   🛡️ UA blacklist: $UA_COUNT patterns configured."
    export TRAEFIK_BAD_USER_AGENTS
fi


if ! docker network inspect anubis-backend >/dev/null 2>&1; then
    docker network create --internal anubis-backend
    echo "   ✅ Created anubis-backend network (internal)."
fi

if ! docker network inspect traefik >/dev/null 2>&1; then
    docker network create traefik
    echo "   ✅ Created traefik network."
fi

# =============================================================================
# PHASE 6: Build Compose File List
# =============================================================================

# --- Apache Detection (sets flag file for compose-files.sh) ---
APACHE_FLAG_FILE=".apache_host_available"

# If we are in the host (dpkg-query exists), do the real check
if command -v dpkg-query >/dev/null 2>&1; then
    if dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -q "ok installed"; then
        export APACHE_HOST_AVAILABLE="true"
        touch "$APACHE_FLAG_FILE"
    else
        export APACHE_HOST_AVAILABLE="false"
        rm -f "$APACHE_FLAG_FILE"
    fi
# If we are in the container (no dpkg-query), rely on the flag file created by the host
elif [ -f "$APACHE_FLAG_FILE" ]; then
    export APACHE_HOST_AVAILABLE="true"
else
    export APACHE_HOST_AVAILABLE="false"
fi

# --- Build compose file list (shared with stop.sh and Makefile) ---
source scripts/compose-files.sh

if [ "$APACHE_HOST_AVAILABLE" == "true" ]; then
    echo "   📋 Apache legacy detected, including logs extension."
fi


echo " --------------------------------------------------------"
echo " [5/6] 👮 Booting security layer..."

if [[ "$CROWDSEC_DISABLE" != "true" ]]; then
    # Smart check: Is it already running and healthy?
    CROWDSEC_ID=$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT_NAME --filter label=com.docker.compose.service=crowdsec | head -n 1)
    CS_STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$CROWDSEC_ID" 2>/dev/null || echo "none")

    if [ "$CS_STATUS" == "healthy" ]; then
        echo "   🛡️ CrowdSec is already operational. Skipping boot."
    else
        echo "   🛡 Booting CrowdSec + Redis..."
        $COMPOSE_CMD $COMPOSE_FILES up -d crowdsec redis
        sleep 1 # Allow terminal to settle

        # Wait for CrowdSec to be healthy
        echo -n "   ⏳ Waiting for CrowdSec API"
        timeout=60
        # Refresh ID in case it was just created
        CROWDSEC_ID=$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT_NAME --filter label=com.docker.compose.service=crowdsec | head -n 1)
        
        while [ -z "$CROWDSEC_ID" ] || [ "$(docker inspect --format='{{.State.Health.Status}}' $CROWDSEC_ID 2>/dev/null)" != "healthy" ]; do
            sleep 2
            echo -n "."
            ((timeout-=2))
            if [ $timeout -le 0 ]; then
                echo ""
                echo "   ❌ Timeout waiting for CrowdSec to become healthy."
                exit 1
            fi
            CROWDSEC_ID=$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT_NAME --filter label=com.docker.compose.service=crowdsec | head -n 1)
        done
        echo " ready!"
        echo "   ✅ CrowdSec operational."
    fi

    # =============================================================================
    # PHASE 8: Register Bouncer API Key
    # =============================================================================
    # Re-register the Traefik Bouncer key on each start to ensure consistency.
    # Delete first (silently) in case it already exists, then add fresh.

    docker exec "$CROWDSEC_ID" cscli bouncers delete traefik-bouncer > /dev/null 2>&1 || true
    docker exec "$CROWDSEC_ID" cscli bouncers add traefik-bouncer --key "${CROWDSEC_API_KEY}" > /dev/null

    if [ $? -eq 0 ]; then
        echo "   🔑 Bouncer key registered."
    else
        echo "⚠️ Error registering bouncer key. Check CrowdSec logs."
        exit 1
    fi

    # =============================================================================
    # PHASE 9: CrowdSec Console Enrollment (Optional)
    # =============================================================================
    # If CROWDSEC_ENROLLMENT_KEY is set, enroll this instance with CrowdSec Console
    # for access to community blocklists and centralized management.

    if [ -n "$CROWDSEC_ENROLLMENT_KEY" ] && [ "$CROWDSEC_ENROLLMENT_KEY" != "REPLACE_ME" ]; then
        echo "   🌐 Enrolling CrowdSec to Console..."
        if docker exec "$CROWDSEC_ID" cscli console enroll "$CROWDSEC_ENROLLMENT_KEY" --name "$(hostname)" 2>/dev/null; then
            echo "   ✅ Successfully enrolled in CrowdSec Console."
        else
            echo "   ⚠️ Console enrollment failed or already enrolled. Continuing..."
        fi
    fi
else
    REDIS_ID=$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT_NAME --filter label=com.docker.compose.service=redis | head -n 1)
    if [ -n "$REDIS_ID" ] && [ "$(docker inspect --format='{{.State.Running}}' $REDIS_ID 2>/dev/null)" == "true" ]; then
        echo "   🛡️ Redis is already operational. Skipping boot."
    else
        echo "   🛡️ Booting Redis (CrowdSec is disabled)..."
        $COMPOSE_CMD $COMPOSE_FILES up -d redis
        sleep 1
        echo "   ✅ Redis operational."
    fi
fi

# =============================================================================
# PHASE 10: Deploy Remaining Services
# =============================================================================
# Now that the security layer is ready, deploy everything else.
# --remove-orphans cleans up any old containers not in current config.


echo " --------------------------------------------------------"
echo " [6/6] 🚀 Deploying application services..."

# If running inside domain-manager, exclude it from the 'up' command to avoid killing this script
if [[ "$DOMAIN_MANAGER_INTERNAL" == "true" ]]; then
    echo "   ℹ️ Internal run detected. Excluding domain-manager from self-restart."
    # Get all services from all compose files, then filter out domain-manager exactly
    SERVICES=$($COMPOSE_CMD $COMPOSE_FILES ps --services | grep -vxE "domain-manager" | xargs)
    $COMPOSE_CMD $COMPOSE_FILES up -d --remove-orphans $SERVICES
else
    $COMPOSE_CMD $COMPOSE_FILES up -d --remove-orphans
fi
sleep 1

echo "   🔍 Verifying Core DNS records..."
CORE_SUBS=("dashboard")
MISSING_DNS=()

# Helper for DNS resolution (cross-platform)
resolve_host() {
    local host="$1"
    if command -v getent >/dev/null 2>&1; then
        getent ahosts "$host" >/dev/null 2>&1
        return $?
    elif command -v host >/dev/null 2>&1; then
        host -t A "$host" >/dev/null 2>&1
        return $?
    elif command -v ping >/dev/null 2>&1; then
        # Ping once, timeout 1s. Mac usage: -c 1 -t 1. Linux usage: -c 1 -W 1.
        # We try a common subset or fallback.
        ping -c 1 -t 1 "$host" >/dev/null 2>&1 || ping -c 1 -W 1 "$host" >/dev/null 2>&1
        return $?
    else
        # Fallback: simple grep in /etc/hosts for local dev, though imperfect for real DNS
        grep -q "[[:space:]]$host" /etc/hosts
        return $?
    fi
}

for sub in "${CORE_SUBS[@]}"; do
    TARGET_FQDN="$sub.$DOMAIN"
    if ! resolve_host "$TARGET_FQDN"; then
        MISSING_DNS+=("$TARGET_FQDN")
    fi
done

if [ ${#MISSING_DNS[@]} -gt 0 ]; then
    echo "      ⚠️ The following core subdomains are not resolvable:"
    for m in "${MISSING_DNS[@]}"; do
        echo "         ➜ $m"
    done
    echo "      👉 ACTION REQUIRED: Please create these DNS records (Type A) pointing to this server."
else
    echo "      ✅ All core DNS records verified."
fi

# =============================================================================
# DONE
# =============================================================================

# ⏲️ Calculate Duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "========================================================"
echo "✅ DEPLOYMENT COMPLETE! (Total time: ${DURATION}s)"
echo "========================================================"
echo ""
echo "🌐 Core Services:"
    echo -e "   ➜ Dashboard Home:  https://${DASHBOARD_SUBDOMAIN:-dashboard}.${DOMAIN}/"
    echo -e "   ➜ Domain Manager:  https://${DASHBOARD_SUBDOMAIN:-dashboard}.${DOMAIN}/domains"
    echo -e "   ➜ Traefik:         https://${DASHBOARD_SUBDOMAIN:-dashboard}.${DOMAIN}/traefik/"
    echo -e "   ➜ Dozzle (Logs):   https://${DASHBOARD_SUBDOMAIN:-dashboard}.${DOMAIN}/dozzle/"
    echo -e "   ➜ Grafana:         https://${DASHBOARD_SUBDOMAIN:-dashboard}.${DOMAIN}/grafana/"
    echo -e "========================================================"
echo ""
