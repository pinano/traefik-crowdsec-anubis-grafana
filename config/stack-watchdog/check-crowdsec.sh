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
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_RECIPIENT_ID}" \
        -d text="🛡️ *CROWDSEC ALERT* [${SERVER_DOMAIN}] 🛡️%0A%0A${MSG}" \
        -d parse_mode="Markdown" > /dev/null
}

# Verify docker socket is available
if [ ! -S /var/run/docker.sock ]; then
    echo -e "${RED}❌ Error: Docker socket not available.${NC}"
    exit 1
fi

# Check if CrowdSec container is running
CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' "$CROWDSEC_CONTAINER" 2>/dev/null)

if [ -z "$CONTAINER_STATUS" ]; then
    echo -e "${RED}❌ CrowdSec container '$CROWDSEC_CONTAINER' not found!${NC}"
    send_telegram "CrowdSec container \`${CROWDSEC_CONTAINER}\` not found!%0A👉 *Action Required:* Check if the container exists and is properly configured."
    exit 1
fi

if [ "$CONTAINER_STATUS" != "running" ]; then
    echo -e "${RED}❌ CrowdSec container is not running (status: $CONTAINER_STATUS)${NC}"
    send_telegram "CrowdSec container is *not running*!%0ACurrent status: \`${CONTAINER_STATUS}\`%0A👉 *Action Required:* Restart the CrowdSec container."
    exit 1
fi

echo -e "${GREEN}✅ CrowdSec container is running${NC}"

# Check LAPI status
LAPI_STATUS=$(docker exec "$CROWDSEC_CONTAINER" cscli lapi status 2>&1)
LAPI_EXIT_CODE=$?

if [ $LAPI_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}❌ CrowdSec LAPI is not healthy!${NC}"
    echo "$LAPI_STATUS"
    send_telegram "CrowdSec LAPI is *not healthy*!%0A%0AError output:%0A\`\`\`%0A$(echo "$LAPI_STATUS" | head -5)%0A\`\`\`%0A👉 *Action Required:* Check CrowdSec logs."
    exit 1
fi

echo -e "${GREEN}✅ CrowdSec LAPI is healthy${NC}"

# Check registered bouncers
BOUNCERS=$(docker exec "$CROWDSEC_CONTAINER" cscli bouncers list -o json 2>/dev/null)
BOUNCER_COUNT=$(echo "$BOUNCERS" | jq 'length' 2>/dev/null || echo "0")

if [ "$BOUNCER_COUNT" = "0" ] || [ -z "$BOUNCER_COUNT" ]; then
    echo -e "${YELLOW}⚠️ No bouncers registered with CrowdSec${NC}"
    send_telegram "No bouncers are registered with CrowdSec!%0A%0A👉 *Action Required:* Register the Traefik bouncer to enable protection."
else
    echo -e "${GREEN}✅ $BOUNCER_COUNT bouncer(s) registered${NC}"
    
    # Check each bouncer's last heartbeat
    STALE_BOUNCERS=""
    CURRENT_TIME=$(date +%s)
    
    # Parse bouncers and check for stale connections (no heartbeat in 5 minutes)
    echo "$BOUNCERS" | jq -r '.[] | "\(.name)|\(.last_pull)"' 2>/dev/null | while IFS='|' read -r name last_pull; do
        if [ -n "$last_pull" ] && [ "$last_pull" != "null" ]; then
            # Convert last_pull to timestamp (format: 2024-01-01T12:00:00Z)
            LAST_PULL_TS=$(date -d "$last_pull" +%s 2>/dev/null)
            if [ -n "$LAST_PULL_TS" ]; then
                DIFF=$((CURRENT_TIME - LAST_PULL_TS))
                if [ $DIFF -gt 300 ]; then
                    MINUTES=$((DIFF / 60))
                    echo -e "${YELLOW}⚠️ Bouncer '$name' last pull was $MINUTES minutes ago${NC}"
                    echo "$name:$MINUTES" >> /tmp/stale_bouncers.txt
                else
                    echo -e "${GREEN}  → Bouncer '$name' is active (last pull: ${DIFF}s ago)${NC}"
                fi
            fi
        fi
    done
    
    # Check if we found stale bouncers
    if [ -f /tmp/stale_bouncers.txt ]; then
        STALE_LIST=$(cat /tmp/stale_bouncers.txt | while IFS=':' read -r name minutes; do
            echo "• *$name*: last pull was ${minutes} minutes ago"
        done)
        send_telegram "Some bouncers appear to be stale:%0A%0A${STALE_LIST}%0A%0A👉 *Action Required:* Check bouncer connectivity."
        rm -f /tmp/stale_bouncers.txt
    fi
fi

# Get current ban statistics
DECISIONS=$(docker exec "$CROWDSEC_CONTAINER" cscli decisions list -o json 2>/dev/null)
DECISION_COUNT=$(echo "$DECISIONS" | jq 'length' 2>/dev/null || echo "0")

if [ "$DECISION_COUNT" = "null" ] || [ -z "$DECISION_COUNT" ]; then
    DECISION_COUNT="0"
fi

echo -e "${GREEN}📊 Active decisions (bans): $DECISION_COUNT${NC}"

# Get metrics summary
ALERTS_24H=$(docker exec "$CROWDSEC_CONTAINER" cscli alerts list --since 24h -o json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
if [ "$ALERTS_24H" = "null" ] || [ -z "$ALERTS_24H" ]; then
    ALERTS_24H="0"
fi

echo -e "${GREEN}📊 Alerts in last 24h: $ALERTS_24H${NC}"

echo ""
echo "✅ CrowdSec health check completed successfully."
echo "📊 Summary:"
echo "   - Container status: running"
echo "   - LAPI: healthy"
echo "   - Registered bouncers: $BOUNCER_COUNT"
echo "   - Active bans: $DECISION_COUNT"
echo "   - Alerts (24h): $ALERTS_24H"
