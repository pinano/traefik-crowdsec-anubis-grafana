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
grafana-test-alert: ## Send a test Telegram message to verify bot token and chat ID
	@echo "🧪 Sending test message via Telegram Bot API..."
	@RESPONSE=$$(curl -sS \
		"https://api.telegram.org/bot$(WATCHDOG_TELEGRAM_BOT_TOKEN)/sendMessage" \
		-d "chat_id=$(WATCHDOG_TELEGRAM_RECIPIENT_ID)" \
		-d "parse_mode=HTML" \
		--data-urlencode "text=🧪 <b>Grafana Alerting – Test OK</b>%0A%0AStack: <code>$(PROJECT_NAME)</code>%0ATime: $$(date '+%Y-%m-%d %H:%M:%S %Z')%0A%0AAlert notifications are correctly configured."); \
	if echo "$$RESPONSE" | grep -q '"ok":true'; then \
		echo "  ✅ Message sent! Check your Telegram bot."; \
	else \
		echo "  ❌ Failed. Response: $$RESPONSE"; \
		echo "  Check WATCHDOG_TELEGRAM_BOT_TOKEN and WATCHDOG_TELEGRAM_RECIPIENT_ID in .env"; \
	fi
