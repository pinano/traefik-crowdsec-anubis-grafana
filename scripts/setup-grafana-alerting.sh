#!/usr/bin/env bash
# scripts/setup-grafana-alerting.sh
# Configures Grafana Alerting (Telegram contact point + notification policy)
# via the Grafana Provisioning REST API.
#
# All API calls are made INSIDE the Grafana container via docker exec,
# so this works regardless of DNS resolution, TLS certificates, or
# whether Traefik is fully ready. No external URL needed.
#
# Called automatically from `make start` and can also be run manually:
#   make grafana-setup-telegram
#
# Exit codes:
#   0 — success or intentional skip (tokens not set, container not running)
#   1 — unexpected script error (set -e)
#
# Environment variables required (loaded from .env by Makefile):
#   PROJECT_NAME, GRAFANA_ADMIN_USER, GRAFANA_ADMIN_PASSWORD
#   WATCHDOG_TELEGRAM_BOT_TOKEN, WATCHDOG_TELEGRAM_RECIPIENT_ID

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────────
GRAFANA_CONTAINER="${PROJECT_NAME:-stack}-grafana-1"
AUTH="${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}"
CONTACT_POINT_NAME="Telegram"

# ─── Helpers ─────────────────────────────────────────────────────────────────
info()    { echo "  $*"; }
success() { echo "  ✅ $*"; }
warn()    { echo "  ⚠️  $*"; }
skip()    { echo "  ℹ️  $*"; exit 0; }

# Run a curl command INSIDE the Grafana container (avoids DNS/TLS/Traefik issues)
grafana_api() {
    docker exec "${GRAFANA_CONTAINER}" \
        curl -sk -u "${AUTH}" "$@"
}

# ─── Guard: skip if Telegram is not configured ───────────────────────────────
if [[ -z "${WATCHDOG_TELEGRAM_BOT_TOKEN:-}" || "${WATCHDOG_TELEGRAM_BOT_TOKEN}" == "REPLACE_ME" ]]; then
    skip "WATCHDOG_TELEGRAM_BOT_TOKEN not configured — skipping Grafana alerting setup."
fi
if [[ -z "${WATCHDOG_TELEGRAM_RECIPIENT_ID:-}" || "${WATCHDOG_TELEGRAM_RECIPIENT_ID}" == "REPLACE_ME" ]]; then
    skip "WATCHDOG_TELEGRAM_RECIPIENT_ID not configured — skipping Grafana alerting setup."
fi

echo ""
echo "🔔 Grafana Alerting setup (Telegram)"
echo "────────────────────────────────────"

# ─── Guard: skip if Docker is not available ──────────────────────────────────
if ! command -v docker &>/dev/null; then
    skip "docker not found in PATH — skipping (run 'make grafana-setup-telegram' once Docker is available)."
fi

# ─── Wait for Grafana container to be running and healthy ─────────────────────
info "Waiting for Grafana container..."
GRAFANA_READY=false
for i in $(seq 1 24); do
    # Check container is running first
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${GRAFANA_CONTAINER}$"; then
        sleep 5
        continue
    fi
    # Then check Grafana's internal health endpoint
    if grafana_api "http://localhost:3000/api/health" 2>/dev/null | grep -q '"database": "ok"'; then
        GRAFANA_READY=true
        break
    fi
    sleep 5
done

if [[ "${GRAFANA_READY}" == "false" ]]; then
    warn "Grafana container '${GRAFANA_CONTAINER}' did not become healthy after 2 minutes."
    warn "Run 'make grafana-setup-telegram' manually once Grafana is up."
    exit 0  # Non-fatal: don't break 'make start'
fi
success "Grafana is up (container: ${GRAFANA_CONTAINER})."

# ─── Check if Telegram contact point already exists ──────────────────────────
info "Checking existing contact points..."
EXISTING=$(grafana_api "http://localhost:3000/api/v1/provisioning/contact-points")

if echo "${EXISTING}" | grep -q "\"name\":\"${CONTACT_POINT_NAME}\""; then
    success "Contact point '${CONTACT_POINT_NAME}' already exists — skipping creation."
    CONTACT_POINT_EXISTS=true
else
    CONTACT_POINT_EXISTS=false
fi

# ─── Create contact point (only if it doesn't exist) ─────────────────────────
if [[ "${CONTACT_POINT_EXISTS}" == "false" ]]; then
    info "Creating '${CONTACT_POINT_NAME}' contact point..."

    # Note: 'message' field is intentionally omitted — the Go template syntax requires
    # embedded double quotes (e.g. {{ if eq .Status "firing" }}) which break inline JSON.
    # Grafana's default Telegram message format is already informative.
    # To customize the message, edit the contact point via the Grafana UI after setup.
    RESPONSE=$(grafana_api -X POST \
        -H "Content-Type: application/json" \
        "http://localhost:3000/api/v1/provisioning/contact-points" \
        --data-raw "{
            \"name\": \"${CONTACT_POINT_NAME}\",
            \"type\": \"telegram\",
            \"settings\": {
                \"chatid\": \"${WATCHDOG_TELEGRAM_RECIPIENT_ID}\",
                \"parse_mode\": \"HTML\",
                \"disable_web_page_preview\": true
            },
            \"secureSettings\": {
                \"bottoken\": \"${WATCHDOG_TELEGRAM_BOT_TOKEN}\"
            },
            \"disableResolveMessage\": false
        }")

    if echo "${RESPONSE}" | grep -q '"uid"'; then
        success "Contact point created."
    else
        warn "Unexpected response: ${RESPONSE}"
    fi
fi

# ─── Set notification policy (only if not already routing to Telegram) ────────
info "Checking notification policy..."
CURRENT_POLICY=$(grafana_api "http://localhost:3000/api/v1/provisioning/policies")
CURRENT_RECEIVER=$(echo "${CURRENT_POLICY}" | grep -o '"receiver":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

if [[ "${CURRENT_RECEIVER}" == "${CONTACT_POINT_NAME}" ]]; then
    success "Notification policy already routes to '${CONTACT_POINT_NAME}' — skipping."
else
    info "Setting notification policy → '${CONTACT_POINT_NAME}'..."
    RESPONSE=$(grafana_api -X PUT \
        -H "Content-Type: application/json" \
        "http://localhost:3000/api/v1/provisioning/policies" \
        --data-raw "{
            \"receiver\": \"${CONTACT_POINT_NAME}\",
            \"group_by\": [\"alertname\", \"severity\"],
            \"group_wait\": \"30s\",
            \"group_interval\": \"5m\",
            \"repeat_interval\": \"4h\",
            \"routes\": [
                {
                    \"receiver\": \"${CONTACT_POINT_NAME}\",
                    \"matchers\": [\"severity = critical\"],
                    \"group_wait\": \"10s\",
                    \"group_interval\": \"2m\",
                    \"repeat_interval\": \"1h\"
                },
                {
                    \"receiver\": \"${CONTACT_POINT_NAME}\",
                    \"matchers\": [\"severity = warning\"],
                    \"group_wait\": \"30s\",
                    \"group_interval\": \"5m\",
                    \"repeat_interval\": \"4h\"
                }
            ]
        }")

    if echo "${RESPONSE}" | grep -q '"receiver"'; then
        success "Notification policy set."
    else
        warn "Unexpected response: ${RESPONSE}"
    fi
fi

echo ""
echo "✅ Grafana Alerting ready. Run 'make grafana-test-alert' to verify."
echo ""
