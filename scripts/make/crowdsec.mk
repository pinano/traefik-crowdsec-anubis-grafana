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
crowdsec-unban: ## Unban an IP address (usage: make crowdsec-unban 123.123.123.123)
	@if [ -z "$(SERVICE_ARGS)" ]; then \
		echo "Error: Please specify at least one IP address (e.g., 'make crowdsec-unban 1.2.3.4')."; \
		exit 1; \
	fi; \
	for ip in $(SERVICE_ARGS); do \
		echo "Removing ban for IP: $$ip..."; \
		$(call check_service,crowdsec,cscli decisions delete --ip $$ip); \
	done
