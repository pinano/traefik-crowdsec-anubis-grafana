
# Makefile - Project Management
# Wraps existing scripts and provides utility commands for the Docker stack.

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default shell
SHELL := /bin/bash

# Default target
.DEFAULT_GOAL := help

# =============================================================================
# TARGETS
# =============================================================================

# =============================================================================
# DOCKER COMPOSE CONFIGURATION
# =============================================================================

# Base Compose files
COMPOSE_FILES := -f docker-compose-traefik-crowdsec-redis.yaml \
                 -f docker-compose-tools.yaml \
                 -f docker-compose-grafana-loki-alloy.yaml \
                 -f docker-compose-domain-manager.yaml

# Add Anubis if generated
ifneq ("$(wildcard docker-compose-anubis-generated.yaml)","")
    COMPOSE_FILES += -f docker-compose-anubis-generated.yaml
endif

# Add Apache logs if flagged (relying on .apache_host_available created by start.sh)
ifneq ("$(wildcard .apache_host_available)","")
    COMPOSE_FILES += -f docker-compose-apache-logs.yaml
endif

# Extract PROJECT_NAME from .env (default to 'stack' if not found)
PROJECT_NAME := $(shell grep '^PROJECT_NAME=' .env 2>/dev/null | cut -d= -f2 || echo stack)

# Suppress warnings for variables set dynamically in start.sh
export TRAEFIK_CONFIG_HASH ?= ""
export TRAEFIK_CERT_RESOLVER ?= ""

# Extract TRAEFIK_ACME_ENV_TYPE from .env
TRAEFIK_ACME_ENV_TYPE := $(shell grep '^TRAEFIK_ACME_ENV_TYPE=' .env 2>/dev/null | cut -d= -f2)

# Base Docker Compose command
DOCKER_COMPOSE := docker compose -p $(PROJECT_NAME) $(COMPOSE_FILES)

# =============================================================================
# TARGETS
# =============================================================================

.PHONY: help
help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: init
init: ## Initialize environment (.env)
	@./scripts/initialize-env.sh

.PHONY: start
start: ## Start the stack (calls start.sh)
	@./scripts/start.sh

.PHONY: stop
stop: ## Stop the stack (calls stop.sh)
	@./scripts/stop.sh

.PHONY: restart
restart: stop start ## Restart the stack

.PHONY: status
status: ## Show stack status (docker compose ps)
	@$(DOCKER_COMPOSE) ps

.PHONY: services
services: ## List available services
	@echo "Available services:"
	@$(DOCKER_COMPOSE) ps --services

.PHONY: logs
logs: ## Follow logs for all containers or a specific service (s=service_name)
ifdef s
	@echo "Following logs for service: $(s)..."
	@sleep 2
	@$(DOCKER_COMPOSE) logs -f $(s)
else
	@echo "Following logs for ALL services... (Use 'make services' to see list)"
	@sleep 2
	@$(DOCKER_COMPOSE) logs -f
endif

.PHONY: shell
shell: ## Open a shell in a container (usage: make shell s=anubis)
ifdef s
	@$(DOCKER_COMPOSE) exec -it $(s) /bin/sh
else
	@echo "Error: Please specify a service name using 's=service_name'."
	@echo ""
	@make services
endif

.PHONY: pull
pull: ## Pull latest images
	@$(DOCKER_COMPOSE) pull

.PHONY: clean
clean: ## Remove generated configuration files (Requires confirmation)
	@echo "⚠️  WARNING: This will permanently delete the following files:"
	@echo "   - config/traefik/dynamic-config/* (Generated Routers)"
	@echo "   - config/traefik/acme.json        (SSL Certificates)"
	@echo ""
	@read -p "Are you sure you want to proceed? [y/N] " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		rm -rf config/traefik/dynamic-config/*; \
		rm -f config/traefik/acme.json; \
		echo "✅ Cleaned generated files."; \
	else \
		echo "Aborted."; \
	fi

# Only show 'certs' target if environment is local
ifeq ($(TRAEFIK_ACME_ENV_TYPE),local)
.PHONY: certs
certs: ## Generate local certificates (calls create-local-certs.sh)
	@./scripts/create-local-certs.sh
endif

.PHONY: validate
validate: ## Validate environment configuration
	@if [ ! -f .env ]; then \
		echo "Error: .env file missing. Run 'make init' first."; \
		exit 1; \
	fi
	@python3 scripts/validate-env.py
