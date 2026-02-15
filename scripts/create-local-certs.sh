#!/bin/bash

# Script to generate local SSL certificates for all domains pointing to 127.0.0.1 in /etc/hosts

# Directory where certs should be stored (relative to project root)
CERT_DIR="config/traefik/certs-local-dev"

# Ensure we are in the project root (simple check for domains.csv)
if [ ! -f "domains.csv" ]; then
    echo "❌ Error: This script must be run from the project root."
    exit 1
fi

# Ensure output directory exists
mkdir -p "$CERT_DIR"

echo "🔍 Scanning /etc/hosts for 127.0.0.1 entries..."

# Extract all hostnames pointing to 127.0.0.1
# 1. grep lines starting with 127.0.0.1
# 2. remove the IP address
# 3. replace spaces/tabs with newlines to get one host per line
# 4. filter out common defaults and empty lines
# 5. sort and uniq
DOMAINS=$(grep "^127\.0\.0\.1" /etc/hosts | sed 's/127\.0\.0\.1//' | tr '[:space:]' '\n' | grep -v "localhost" | grep -v "broadcasthost" | grep -v "^$" | sort -u | tr '\n' ' ')

if [ -z "$DOMAINS" ]; then
    echo "❌ No local domains found in /etc/hosts (pointing to 127.0.0.1, excluding localhost)."
    exit 1
fi

echo "✅ Found domains: $DOMAINS"

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "❌ Error: 'mkcert' is not installed. Please install it first (e.g., brew install mkcert)."
    exit 1
fi

echo "🚀 Generating certificates with mkcert..."

# Generate certificate
# We use the array of domains as separate arguments to mkcert
mkcert -cert-file "$CERT_DIR/local-cert.pem" -key-file "$CERT_DIR/local-key.pem" $DOMAINS

if [ $? -eq 0 ]; then
    echo "✨ Successfully generated local certificates:"
    echo "   - Cert: $CERT_DIR/local-cert.pem"
    echo "   - Key:  $CERT_DIR/local-key.pem"
else
    echo "❌ Error: mkcert failed to generate certificates."
    exit 1
fi
