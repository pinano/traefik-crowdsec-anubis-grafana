# Local Certificates Targets
# Included conditionally in main Makefile

.PHONY: certs
certs: ## Generate local certificates (calls create-local-certs.sh)
	@./scripts/create-local-certs.sh
