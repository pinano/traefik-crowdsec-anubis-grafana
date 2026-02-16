#!/bin/bash

docker compose -p stack -f docker-compose-domain-manager.yaml up -d --build --force-recreate domain-manager
