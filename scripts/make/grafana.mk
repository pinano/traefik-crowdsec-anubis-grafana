# =============================================================================
# GRAFANA ALERTING SETUP
# =============================================================================
# All API calls go through 'docker exec' inside the Grafana container,
# bypassing Traefik, DNS and TLS. Works in any environment.

GRAFANA_CONTAINER := $(PROJECT_NAME)-grafana-1
GRAFANA_AUTH      := $(GRAFANA_ADMIN_USER):$(GRAFANA_ADMIN_PASSWORD)

.PHONY: grafana-setup-telegram
grafana-setup-telegram: ## Configure Grafana Alerting: Telegram contact point + notification policy
	@PROJECT_NAME=$(PROJECT_NAME) \
	 GRAFANA_ADMIN_USER=$(GRAFANA_ADMIN_USER) \
	 GRAFANA_ADMIN_PASSWORD=$(GRAFANA_ADMIN_PASSWORD) \
	 WATCHDOG_TELEGRAM_BOT_TOKEN=$(WATCHDOG_TELEGRAM_BOT_TOKEN) \
	 WATCHDOG_TELEGRAM_RECIPIENT_ID=$(WATCHDOG_TELEGRAM_RECIPIENT_ID) \
	 bash ./scripts/setup-grafana-alerting.sh

.PHONY: grafana-test-alert
grafana-test-alert: ## Send a test alert via Grafana to Telegram
	@echo "🧪 Sending test alert to Telegram..."
	@docker exec $(GRAFANA_CONTAINER) \
		curl -sk -X POST \
		-H "Content-Type: application/json" \
		-u "$(GRAFANA_AUTH)" \
		"http://localhost:3000/api/v1/provisioning/contact-points/test" \
		--data-raw '{"receivers": [{"name": "Telegram"}]}' \
		| python3 -m json.tool 2>/dev/null || echo "Done."
