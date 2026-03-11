#!/bin/sh

# CrowdSec Health Check Script - Monitors CrowdSec status via Docker
# Sends Telegram alert if CrowdSec or bouncers are having issues

# Configuration
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-crowdsec}"
CROWDSEC_CHECK_INTERVAL=${WATCHDOG_CROWDSEC_CHECK_INTERVAL:-3600}
TELEGRAM_BOT_TOKEN="${WATCHDOG_TELEGRAM_BOT_TOKEN}"
TELEGRAM_RECIPIENT_ID="${WATCHDOG_TELEGRAM_RECIPIENT_ID}"

# Colors for local logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "🛡️ Starting CrowdSec health check..."

# Function to send Telegram alert
send_telegram() {
    MSG="$1"
    # Use backticks instead of square brackets for SERVER_DOMAIN to avoid Markdown parsing issues
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_RECIPIENT_ID}" \
        -d text="🛡️ *CROWDSEC ALERT* 🛡️%0A[\`${SERVER_DOMAIN}\`]%0A%0A${MSG}" \
        -d parse_mode="Markdown" > /dev/null
}

# Verify docker socket is available
if [ ! -S /var/run/docker.sock ]; then
    printf '%b\n' "${RED}❌ Error: Docker socket not available.${NC}"
    exit 1
fi

# Check if CrowdSec container is running (with retries for robustness)
MAX_RETRIES=3
RETRY_COUNT=0
CONTAINER_STATUS=""
REAL_CONTAINER_ID=""

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    # Try finding by label first (more robust with dynamic naming)
    REAL_CONTAINER_ID=$(docker ps -aq --filter "label=com.docker.compose.service=crowdsec" | head -n 1)
    
    # If not found by label, fallback to name for custom non-compose setups
    if [ -z "$REAL_CONTAINER_ID" ]; then
        REAL_CONTAINER_ID=$(docker ps -aqf "name=$CROWDSEC_CONTAINER" | head -n 1)
    fi

    if [ -n "$REAL_CONTAINER_ID" ]; then
        CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' "$REAL_CONTAINER_ID" 2>/dev/null)
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        printf '%b\n' "${YELLOW}⚠️ Warning: CrowdSec container not found (Attempt $RETRY_COUNT/$MAX_RETRIES). Retrying in 2s...${NC}"
        sleep 2
    fi
done

if [ -z "$REAL_CONTAINER_ID" ] || [ -z "$CONTAINER_STATUS" ]; then
    printf '%b\n' "${RED}❌ CrowdSec container not found or Docker API error after $MAX_RETRIES attempts!${NC}"
    send_telegram "CrowdSec container not found or Docker API error!%0A👉 *Action Required:* Check if the container exists and is properly configured. If necessary, you can try restarting it (e.g., \`make restart crowdsec\`)."
    exit 1
fi

# Update variable to use the ID for subsequent commands
CROWDSEC_CONTAINER="$REAL_CONTAINER_ID"

if [ "$CONTAINER_STATUS" != "running" ]; then
    printf '%b\n' "${RED}❌ CrowdSec container is not running (status: $CONTAINER_STATUS)${NC}"
    send_telegram "CrowdSec container is *not running*!%0ACurrent status: \`${CONTAINER_STATUS}\`%0A👉 *Action Required:* Restart the CrowdSec container (e.g., \`make restart crowdsec\`)."
    exit 1
fi

printf '%b\n' "${GREEN}✅ CrowdSec container is running${NC}"

# Check LAPI status
LAPI_STATUS=$(docker exec "$CROWDSEC_CONTAINER" cscli lapi status 2>&1)
LAPI_EXIT_CODE=$?

if [ $LAPI_EXIT_CODE -ne 0 ]; then
    printf '%b\n' "${RED}❌ CrowdSec LAPI is not healthy!${NC}"
    echo "$LAPI_STATUS"
    send_telegram "CrowdSec LAPI is *not healthy*!%0A%0AError output:%0A\`\`\`%0A$(echo "$LAPI_STATUS" | head -5)%0A\`\`\`%0A👉 *Action Required:* Check CrowdSec logs, and if necessary, restart the container (e.g., \`make restart crowdsec\`)."
    exit 1
fi

printf '%b\n' "${GREEN}✅ CrowdSec LAPI is healthy${NC}"

# Check registered bouncers
BOUNCERS=$(docker exec "$CROWDSEC_CONTAINER" cscli bouncers list -o json 2>/dev/null)
BOUNCER_COUNT=$(echo "$BOUNCERS" | jq 'length' 2>/dev/null || echo "0")

if [ "$BOUNCER_COUNT" = "0" ] || [ -z "$BOUNCER_COUNT" ]; then
    printf '%b\n' "${YELLOW}⚠️ No bouncers registered with CrowdSec${NC}"
    send_telegram "No bouncers are registered with CrowdSec!%0A%0A👉 *Action Required:* Register the Traefik bouncer to enable protection. If they should be registered, try restarting the container (e.g., \`make restart crowdsec\`)."
else
    printf '%b\n' "${GREEN}✅ $BOUNCER_COUNT bouncer(s) registered${NC}"
    
    CURRENT_TIME=$(date +%s)
    STALE_THRESHOLD=600 # 10 minutes (to avoid false positives with Traefik plugins)
    PRUNE_THRESHOLD=172800 # 48 hours (to cleanup very old stale entries)
    
    # Use a temp directory to group bouncers
    GROUP_DIR=$(mktemp -d /tmp/crowdsec_bouncers_XXXXXX)
    
    # Process bouncers and group them by base name
    # NOTE: We read into a temp file first to avoid subshell variable scope issues
    BOUNCER_LIST_FILE=$(mktemp /tmp/crowdsec_list_XXXXXX)
    echo "$BOUNCERS" | jq -r '.[] | "\(.name)|\(.last_pull)"' 2>/dev/null > "$BOUNCER_LIST_FILE"

    while IFS='|' read -r full_name last_pull; do
        # Extract base name (e.g., traefik-bouncer from traefik-bouncer@172.19.0.6)
        base_name=$(echo "$full_name" | cut -d'@' -f1)
        
        IS_STALE=1
        IS_REALLY_OLD=0
        
        if [ -n "$last_pull" ] && [ "$last_pull" != "null" ]; then
            # Handle possible multiple instances by taking the first one if jq returned multiple
            last_pull_actual=$(echo "$last_pull" | head -n 1)
            LAST_PULL_TS=$(date -d "$last_pull_actual" +%s 2>/dev/null)
            
            # Only proceed if we got a valid timestamp
            if [ -n "$LAST_PULL_TS" ] && echo "$LAST_PULL_TS" | grep -q '^[0-9]\+$'; then
                DIFF=$((CURRENT_TIME - LAST_PULL_TS))
                [ $DIFF -le $STALE_THRESHOLD ] && IS_STALE=0
                [ $DIFF -gt $PRUNE_THRESHOLD ] && IS_REALLY_OLD=1
            fi
        fi

        # Auto-prune very old bouncers — do this BEFORE recording group status
        if [ $IS_REALLY_OLD -eq 1 ]; then
            DIFF_H=$((( CURRENT_TIME - LAST_PULL_TS ) / 3600))
            printf '%b\n' "${YELLOW}🧹 Auto-pruning very old bouncer: $full_name (last pull: ${DIFF_H}h ago)${NC}"
            docker exec "$CROWDSEC_CONTAINER" cscli bouncers delete "$full_name" > /dev/null 2>&1
            continue # Skip to next bouncer — don't record this one in group status
        fi

        # Record status for the group (only for non-pruned bouncers)
        if [ $IS_STALE -eq 0 ]; then
            touch "$GROUP_DIR/${base_name}.active"
        else
            echo "$full_name" >> "$GROUP_DIR/${base_name}.stale_list"
        fi
    done < "$BOUNCER_LIST_FILE"
    rm -f "$BOUNCER_LIST_FILE"
    
    # Evaluate groups and build alert message
    STALE_ALERTS=""
    for group_file in "$GROUP_DIR"/*.stale_list; do
        [ ! -f "$group_file" ] && continue
        
        base_name=$(basename "$group_file" .stale_list)
        
        # Only alert if there are NO active instances in this group
        if [ ! -f "$GROUP_DIR/${base_name}.active" ]; then
            while read -r name; do
                # Find the specific minutes for this name to include in alert
                last_pull=$(echo "$BOUNCERS" | jq -r ".[] | select(.name==\"$name\") | .last_pull" | head -n 1)
                
                MSG_TIME=""
                if [ -n "$last_pull" ] && [ "$last_pull" != "null" ]; then
                    LAST_PULL_TS=$(date -d "$last_pull" +%s 2>/dev/null)
                    if [ -n "$LAST_PULL_TS" ] && echo "$LAST_PULL_TS" | grep -q '^[0-9]\+$'; then
                        MINUTES=$(((CURRENT_TIME - LAST_PULL_TS) / 60))
                        MSG_TIME="${MINUTES} minutes ago"
                    else
                        MSG_TIME="unknown time"
                    fi
                else
                    MSG_TIME="never"
                fi
                
                STALE_ALERTS="${STALE_ALERTS}• *$name*: last pull was ${MSG_TIME}%0A"
                printf '%b\n' "${YELLOW}⚠️ Bouncer '$name' is STALE (last pull: ${MSG_TIME})${NC}"
            done < "$group_file"
        else
            printf '%b\n' "${GREEN}✅ Group '$base_name' is active (some instances are stale but at least one is healthy)${NC}"
        fi
    done
    
    if [ -n "$STALE_ALERTS" ]; then
        send_telegram "Some bouncers appear to be stale:%0A%0A${STALE_ALERTS}%0A👉 *Action Required:* Access the host to check CrowdSec log/status. If the issue persists, try restarting it (e.g., \`make restart crowdsec\`)."
    fi
    
    rm -rf "$GROUP_DIR"
fi

# Get current ban statistics
DECISIONS=$(docker exec "$CROWDSEC_CONTAINER" cscli decisions list -o json 2>/dev/null)
DECISION_COUNT=$(echo "$DECISIONS" | jq 'length' 2>/dev/null || echo "0")

if [ "$DECISION_COUNT" = "null" ] || [ -z "$DECISION_COUNT" ]; then
    DECISION_COUNT="0"
fi

printf '%b\n' "${GREEN}📊 Active decisions (bans): $DECISION_COUNT${NC}"

# Get metrics summary
ALERTS_24H=$(docker exec "$CROWDSEC_CONTAINER" cscli alerts list --since 24h -o json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
if [ "$ALERTS_24H" = "null" ] || [ -z "$ALERTS_24H" ]; then
    ALERTS_24H="0"
fi

printf '%b\n' "${GREEN}📊 Alerts in last 24h: $ALERTS_24H${NC}"

echo ""
echo "✅ CrowdSec health check completed successfully."
echo "📊 Summary:"
echo "   - Container status: running"
echo "   - LAPI: healthy"
echo "   - Registered bouncers: $BOUNCER_COUNT"
echo "   - Active bans: $DECISION_COUNT"
echo "   - Alerts (24h): $ALERTS_24H"
