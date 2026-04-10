# =============================================================================
# GRAFANA ALERTING SETUP
# =============================================================================

# Internal: auth for API test commands
GRAFANA_API_URL  := https://$(DASHBOARD_SUBDOMAIN).$(DOMAIN)/grafana/api
GRAFANA_AUTH     := $(GRAFANA_ADMIN_USER):$(GRAFANA_ADMIN_PASSWORD)

.PHONY: grafana-setup-telegram
grafana-setup-telegram: ## Configure Grafana Alerting: Telegram contact point + notification policy
	@DASHBOARD_SUBDOMAIN=$(DASHBOARD_SUBDOMAIN) \
	 DOMAIN=$(DOMAIN) \
	 GRAFANA_ADMIN_USER=$(GRAFANA_ADMIN_USER) \
	 GRAFANA_ADMIN_PASSWORD=$(GRAFANA_ADMIN_PASSWORD) \
	 WATCHDOG_TELEGRAM_BOT_TOKEN=$(WATCHDOG_TELEGRAM_BOT_TOKEN) \
	 WATCHDOG_TELEGRAM_RECIPIENT_ID=$(WATCHDOG_TELEGRAM_RECIPIENT_ID) \
	 bash ./scripts/setup-grafana-alerting.sh

.PHONY: grafana-test-alert
grafana-test-alert: ## Send a test alert via Grafana to Telegram
	@echo "🧪 Sending test alert to Telegram..."
	@curl -sk -X POST \
		-H "Content-Type: application/json" \
		-u "$(GRAFANA_AUTH)" \
		"$(GRAFANA_API_URL)/v1/provisioning/contact-points/test" \
		--data-raw '{"receivers": [{"name": "Telegram"}]}' \
		| python3 -m json.tool 2>/dev/null || echo "Done."
