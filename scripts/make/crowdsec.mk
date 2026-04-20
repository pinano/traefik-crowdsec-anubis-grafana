# CrowdSec Targets
# Included conditionally in main Makefile

.PHONY: crowdsec-metrics
crowdsec-metrics: ## Show CrowdSec metrics (parsed logs, overflows)
	@$(call check_service,crowdsec,cscli metrics)

.PHONY: crowdsec-decisions
crowdsec-decisions: ## List active CrowdSec decisions (bans)
	@$(call check_service,crowdsec,cscli decisions list)

.PHONY: crowdsec-alerts
crowdsec-alerts: ## List recent CrowdSec alerts
	@$(call check_service,crowdsec,cscli alerts list)

.PHONY: crowdsec-unban
crowdsec-unban: ## Unban an IP address (usage: make crowdsec-unban 1.2.3.4)
	@if [ -z "$(SERVICE_ARGS)" ]; then \
		echo "Error: Please specify at least one IP address (e.g., 'make crowdsec-unban 1.2.3.4')."; \
		exit 1; \
	fi; \
	for ip in $(SERVICE_ARGS); do \
		echo "Removing ban for IP: $$ip..."; \
		$(call check_service,crowdsec,cscli decisions delete --ip $$ip); \
	done

.PHONY: crowdsec-ban
crowdsec-ban: ## Ban an IP address manually (usage: make crowdsec-ban 1.2.3.4)
	@if [ -z "$(SERVICE_ARGS)" ]; then \
		echo "Error: Please specify at least one IP address (e.g., 'make crowdsec-ban 1.2.3.4')."; \
		exit 1; \
	fi; \
	for ip in $(SERVICE_ARGS); do \
		echo "Adding ban for IP: $$ip..."; \
		$(call check_service,crowdsec,cscli decisions add --ip $$ip --reason 'manual ban'); \
	done

.PHONY: cscli-ban
cscli-ban: crowdsec-ban ## Alias for crowdsec-ban (usage: make cscli-ban 1.2.3.4)

.PHONY: crowdsec-appsec
crowdsec-appsec: ## Show AppSec WAF status: loaded configs, rules, and metrics
	@echo "=== AppSec Configs ==="
	@$(call check_service,crowdsec,cscli appsec-configs list)
	@echo ""
	@echo "=== AppSec Rules (summary) ==="
	@$(call check_service,crowdsec,cscli appsec-rules list)
	@echo ""
	@echo "=== AppSec Metrics ==="
	@$(call check_service,crowdsec,cscli metrics show appsec)
