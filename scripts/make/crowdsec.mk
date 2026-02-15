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
