#!/usr/bin/env bash
# scripts/setup-grafana-alerting.sh
# Configures Grafana Alerting (Telegram contact point + notification policy)
# via the Grafana Provisioning REST API.
#
# Called automatically from `make start` and can also be run manually:
#   make grafana-setup-telegram
#
# Exit codes:
#   0 — success or intentional skip (tokens not set, Grafana not reachable)
#   1 — unexpected failure (use for manual invocation debugging)
#
# Environment variables required (loaded from .env by Makefile):
#   GRAFANA_ADMIN_USER, GRAFANA_ADMIN_PASSWORD
#   WATCHDOG_TELEGRAM_BOT_TOKEN, WATCHDOG_TELEGRAM_RECIPIENT_ID
#   DASHBOARD_SUBDOMAIN, DOMAIN

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────────
GRAFANA_URL="https://${DASHBOARD_SUBDOMAIN}.${DOMAIN}/grafana"
GRAFANA_API="${GRAFANA_URL}/api"
AUTH="${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASSWORD}"
CONTACT_POINT_NAME="Telegram"

# ─── Helpers ─────────────────────────────────────────────────────────────────
info()    { echo "  $*"; }
success() { echo "  ✅ $*"; }
warn()    { echo "  ⚠️  $*"; }
skip()    { echo "  ℹ️  $*"; exit 0; }

grafana_api() {
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

# ─── Wait for Grafana to be reachable ────────────────────────────────────────
info "Waiting for Grafana..."
GRAFANA_READY=false
for i in $(seq 1 24); do
    if grafana_api "${GRAFANA_API}/health" 2>/dev/null | grep -q '"database": "ok"'; then
        GRAFANA_READY=true
        break
    fi
    sleep 5
done

if [[ "${GRAFANA_READY}" == "false" ]]; then
    warn "Grafana did not respond after 2 minutes."
    warn "Run 'make grafana-setup-telegram' manually once the stack is healthy."
    exit 0  # Non-fatal: don't break 'make start'
fi
success "Grafana is up."

# ─── Check if Telegram contact point already exists ──────────────────────────
info "Checking existing contact points..."
EXISTING=$(grafana_api "${GRAFANA_API}/v1/provisioning/contact-points")
CP_UID=$(echo "${EXISTING}" | grep -o '"uid":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

# Find if the Telegram one exists by name
if echo "${EXISTING}" | grep -q "\"name\":\"${CONTACT_POINT_NAME}\""; then
    success "Contact point '${CONTACT_POINT_NAME}' already exists — skipping creation."
    CONTACT_POINT_EXISTS=true
else
    CONTACT_POINT_EXISTS=false
fi

# ─── Create contact point (only if it doesn't exist) ─────────────────────────
if [[ "${CONTACT_POINT_EXISTS}" == "false" ]]; then
    info "Creating '${CONTACT_POINT_NAME}' contact point..."

    # chatid is passed as a JSON string (quoted) — avoids Grafana YAML type inference bug
    MESSAGE='{{ if eq .Status "firing" }}🔴{{ else }}✅{{ end }} <b>{{ .CommonLabels.alertname }}</b>\n\n{{ range .Alerts }}{{- if eq .Status "firing" }}🔥 <b>FIRING</b>{{ else }}✅ <b>RESOLVED</b>{{ end }}\n📌 <b>Severity:</b> {{ .Labels.severity }}\n📝 {{ .Annotations.summary }}\n{{ if .Annotations.description }}💬 {{ .Annotations.description }}\n{{ end }}{{ end }}'

    RESPONSE=$(grafana_api -X POST \
        -H "Content-Type: application/json" \
        "${GRAFANA_API}/v1/provisioning/contact-points" \
        --data-raw "{
            \"name\": \"${CONTACT_POINT_NAME}\",
            \"type\": \"telegram\",
            \"settings\": {
                \"chatid\": \"${WATCHDOG_TELEGRAM_RECIPIENT_ID}\",
                \"parse_mode\": \"HTML\",
                \"disable_web_page_preview\": true,
                \"message\": \"${MESSAGE}\"
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

# ─── Set notification policy (only if receiver is not already Telegram) ───────
info "Checking notification policy..."
CURRENT_POLICY=$(grafana_api "${GRAFANA_API}/v1/provisioning/policies")
CURRENT_RECEIVER=$(echo "${CURRENT_POLICY}" | grep -o '"receiver":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

if [[ "${CURRENT_RECEIVER}" == "${CONTACT_POINT_NAME}" ]]; then
    success "Notification policy already routes to '${CONTACT_POINT_NAME}' — skipping."
else
    info "Setting notification policy → '${CONTACT_POINT_NAME}'..."
    RESPONSE=$(grafana_api -X PUT \
        -H "Content-Type: application/json" \
        "${GRAFANA_API}/v1/provisioning/policies" \
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
