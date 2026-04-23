#!/usr/bin/env bash
# =============================================================================
# geoblock.sh — Ban or unban all IP ranges for one or more countries via CrowdSec
#
# Usage:
#   ./scripts/geoblock.sh ban   CN RU KP        # Ban China, Russia, North Korea
#   ./scripts/geoblock.sh unban CN              # Unban China
#
# Country codes must be ISO 3166-1 alpha-2 (two letters, case-insensitive).
# IP ranges sourced from https://www.ipdeny.com/ipblocks/data/aggregated/
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# -----------------------------------------------------------------------------
# Validate arguments
# -----------------------------------------------------------------------------
if [ $# -lt 2 ]; then
    echo "Usage: $0 {ban|unban} COUNTRY [COUNTRY ...]"
    echo "       $0 ban   CN RU KP"
    echo "       $0 unban CN"
    exit 1
fi

ACTION="${1,,}"  # lowercase
shift
COUNTRIES=("$@")

if [[ "$ACTION" != "ban" && "$ACTION" != "unban" ]]; then
    die "Unknown action '${ACTION}'. Must be 'ban' or 'unban'."
fi

# -----------------------------------------------------------------------------
# Check CrowdSec is running
# -----------------------------------------------------------------------------
if ! docker compose ps crowdsec 2>/dev/null | grep -q "running\|Up"; then
    die "CrowdSec container is not running. Start the stack first."
fi

CSCLI="docker compose exec crowdsec cscli"

# -----------------------------------------------------------------------------
# Process each country
# -----------------------------------------------------------------------------
TOTAL_OK=0
TOTAL_FAIL=0

for RAW_COUNTRY in "${COUNTRIES[@]}"; do
    COUNTRY="${RAW_COUNTRY^^}"  # uppercase

    if [[ ! "$COUNTRY" =~ ^[A-Z]{2}$ ]]; then
        error "Invalid country code '${COUNTRY}' — must be 2 letters (ISO 3166-1 alpha-2). Skipping."
        (( TOTAL_FAIL++ )) || true
        continue
    fi

    LOWER_COUNTRY="${COUNTRY,,}"
    IPDENY_URL="https://www.ipdeny.com/ipblocks/data/aggregated/${LOWER_COUNTRY}-aggregated.zone"

    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
    echo -e "${BOLD} Country: ${CYAN}${COUNTRY}${RESET}  │  Action: ${YELLOW}${ACTION^^}${RESET}"
    echo -e "${BOLD}══════════════════════════════════════════════${RESET}"

    info "Fetching IP ranges from IPDeny..."
    HTTP_STATUS=$(curl -s -o /tmp/geoblock_ranges.txt -w "%{http_code}" "${IPDENY_URL}")

    if [[ "$HTTP_STATUS" != "200" ]]; then
        error "Failed to fetch ranges for '${COUNTRY}' (HTTP ${HTTP_STATUS}). Unknown country code?"
        rm -f /tmp/geoblock_ranges.txt
        (( TOTAL_FAIL++ )) || true
        continue
    fi

    RANGE_COUNT=$(wc -l < /tmp/geoblock_ranges.txt | tr -d ' ')
    if [[ "$RANGE_COUNT" -eq 0 ]]; then
        warn "No IP ranges found for '${COUNTRY}'. Skipping."
        (( TOTAL_FAIL++ )) || true
        continue
    fi

    info "Found ${RANGE_COUNT} CIDR ranges for ${COUNTRY}."

    OK=0
    FAIL=0

    if [[ "$ACTION" == "ban" ]]; then
        REASON="geoblock-country-${COUNTRY}"
        DURATION="8760h"  # 1 year

        info "Applying bans (reason: ${REASON}, duration: ${DURATION})..."
        while IFS= read -r CIDR; do
            [[ -z "$CIDR" || "$CIDR" == \#* ]] && continue
            if $CSCLI decisions add \
                    --range "$CIDR" \
                    --reason "$REASON" \
                    --duration "$DURATION" \
                    --type ban \
                    > /dev/null 2>&1; then
                (( OK++ )) || true
            else
                warn "Failed to ban range ${CIDR}"
                (( FAIL++ )) || true
            fi
        done < /tmp/geoblock_ranges.txt

        success "Banned ${OK} ranges for ${COUNTRY}."
        [[ "$FAIL" -gt 0 ]] && warn "${FAIL} ranges failed."

    else
        REASON="geoblock-country-${COUNTRY}"

        info "Removing bans for reason '${REASON}'..."
        # Bulk delete by reason — much faster than per-CIDR deletes
        if $CSCLI decisions delete \
                --reason "$REASON" \
                > /dev/null 2>&1; then
            success "Removed all bans with reason '${REASON}' for ${COUNTRY}."
            (( OK++ )) || true
        else
            # Fallback: delete range-by-range (catches edge cases)
            warn "Bulk delete by reason failed or matched nothing — trying per-range fallback..."
            while IFS= read -r CIDR; do
                [[ -z "$CIDR" || "$CIDR" == \#* ]] && continue
                if $CSCLI decisions delete \
                        --range "$CIDR" \
                        > /dev/null 2>&1; then
                    (( OK++ )) || true
                else
                    (( FAIL++ )) || true
                fi
            done < /tmp/geoblock_ranges.txt
            success "Removed bans: ${OK} ranges for ${COUNTRY}."
            [[ "$FAIL" -gt 0 ]] && warn "${FAIL} ranges had no active decision (already unbanned?)."
        fi
    fi

    rm -f /tmp/geoblock_ranges.txt
    (( TOTAL_OK++ )) || true
done

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD} Summary${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "  Countries processed: ${TOTAL_OK}"
echo -e "  Countries skipped:   ${TOTAL_FAIL}"
if [[ "$TOTAL_FAIL" -gt 0 ]]; then
    echo -e "  ${YELLOW}Some countries failed — check output above.${RESET}"
fi
echo ""
