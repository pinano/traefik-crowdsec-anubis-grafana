#!/bin/sh

# DNS Check Script - Verifies all domains in domains.csv point to the host IP
# Sends Telegram alert if any domain has mismatched DNS

# Configuration
DOMAINS_FILE="/domains.csv"
DNS_CHECK_INTERVAL=${DNS_CHECK_INTERVAL:-21600}
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_RECIPIENT_ID="${TELEGRAM_RECIPIENT_ID}"
TRAEFIK_LISTEN_IP="${TRAEFIK_LISTEN_IP}"

# Colors for local logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "🔍 Starting DNS verification check..."

# Function to send Telegram alert
send_telegram() {
    MSG="$1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_RECIPIENT_ID}" \
        -d text="🌐 *DNS ALERT* [${SERVER_DOMAIN}] 🌐%0A%0A${MSG}" \
        -d parse_mode="Markdown" > /dev/null
}

# Verify requirements
if ! command -v dig > /dev/null 2>&1 || ! command -v curl > /dev/null 2>&1; then
    echo "❌ Error: dig (bind-tools) and curl are required."
    exit 1
fi

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "❌ Error: $DOMAINS_FILE not found."
    exit 1
fi

# Determine the expected IP
# If TRAEFIK_LISTEN_IP is empty or 0.0.0.0, auto-detect public IP
# Otherwise, use the configured IP
if [ -z "$TRAEFIK_LISTEN_IP" ] || [ "$TRAEFIK_LISTEN_IP" = "0.0.0.0" ]; then
    echo "📡 Auto-detecting public IP..."
    HOST_IP=$(curl -s --max-time 10 ifconfig.me)
    if [ -z "$HOST_IP" ]; then
        echo "⚠️ Warning: Could not detect public IP. Trying alternative..."
        HOST_IP=$(curl -s --max-time 10 icanhazip.com)
    fi
    if [ -z "$HOST_IP" ]; then
        echo "❌ Error: Could not detect public IP."
        send_telegram "Could not detect public IP for DNS verification."
        exit 1
    fi
    echo "🌐 Detected public IP: $HOST_IP"
else
    HOST_IP="$TRAEFIK_LISTEN_IP"
    echo "🌐 Using configured IP: $HOST_IP"
fi

# Counters
TOTAL=0
ERRORS=0
MISMATCHED_DOMAINS=""

# Read domains from CSV (first column, skip comments and empty lines)
while IFS=, read -r domain rest || [ -n "$domain" ]; do
    # Skip empty lines and comments
    domain=$(echo "$domain" | xargs)
    case "$domain" in
        ""|\#*) continue ;;
    esac

    TOTAL=$((TOTAL + 1))
    
    # Resolve DNS A record
    RESOLVED_IP=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    
    if [ -z "$RESOLVED_IP" ]; then
        echo -e "${YELLOW}[WARN] $domain - No A record found${NC}"
        ERRORS=$((ERRORS + 1))
        MISMATCHED_DOMAINS="${MISMATCHED_DOMAINS}• *${domain}*: No A record found%0A"
    elif [ "$RESOLVED_IP" != "$HOST_IP" ]; then
        echo -e "${RED}[FAIL] $domain -> $RESOLVED_IP (expected: $HOST_IP)${NC}"
        ERRORS=$((ERRORS + 1))
        MISMATCHED_DOMAINS="${MISMATCHED_DOMAINS}• *${domain}*: Points to \`${RESOLVED_IP}\` instead of \`${HOST_IP}\`%0A"
    else
        echo -e "${GREEN}[OK] $domain -> $RESOLVED_IP${NC}"
    fi
done < "$DOMAINS_FILE"

# Send alert if there are mismatches
if [ $ERRORS -gt 0 ]; then
    MESSAGE="Found *${ERRORS}* domain(s) with DNS issues:%0A%0A${MISMATCHED_DOMAINS}%0A👉 *Action Required:* Update DNS records to point to \`${HOST_IP}\`"
    send_telegram "$MESSAGE"
    echo -e "${RED}⚠️ DNS check completed with $ERRORS error(s). Alert sent.${NC}"
else
    echo -e "${GREEN}✅ DNS check completed. All $TOTAL domains point correctly to $HOST_IP${NC}"
fi

echo "📊 Summary: $TOTAL domains checked, $ERRORS with issues."
