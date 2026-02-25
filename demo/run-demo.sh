#!/bin/bash
# Qualys Container Runtime Security (CRS) - Interactive Demo
# Walks through all key features of the qcr CLI

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EVENTGEN_DIR="${PROJECT_DIR}/eventgen"
QCR="${EVENTGEN_DIR}/bin/qcr"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${BLUE}  $1${RESET}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

section() {
    echo ""
    echo -e "${BOLD}${CYAN}── $1 ──${RESET}"
    echo -e "${YELLOW}$2${RESET}"
    echo ""
}

run_cmd() {
    echo -e "${GREEN}\$ $*${RESET}"
    echo ""
    "$@" 2>&1 || true
    echo ""
}

pause() {
    echo -e "${PURPLE}Press Enter to continue...${RESET}"
    read -r
}

skip_msg() {
    echo -e "${YELLOW}  Skipping: $1${RESET}"
    echo ""
}

# ─────────────────────────────────────────────────────────────
# Welcome
# ─────────────────────────────────────────────────────────────
clear
banner "Qualys Container Runtime Security (CRS) Demo"
echo -e "  This demo walks through the key features of the ${BOLD}qcr${RESET} CLI."
echo -e "  Each section will show a command and its output."
echo -e "  Press Enter between sections to advance."
echo ""
pause

# ─────────────────────────────────────────────────────────────
# 1. Build & Version
# ─────────────────────────────────────────────────────────────
banner "1. Build & Version"

section "Building the qcr binary" \
    "Compiles the Go binary from eventgen/cmd/main.go"
(cd "${EVENTGEN_DIR}" && run_cmd make build)

section "Version information" \
    "Shows the current build version and timestamp"
run_cmd "${QCR}" version

pause

# ─────────────────────────────────────────────────────────────
# 2. Event Catalog
# ─────────────────────────────────────────────────────────────
banner "2. Event Catalog"

section "List all security events" \
    "QCR ships with 40 security events across MITRE ATT&CK categories"
run_cmd "${QCR}" events -list

pause

# ─────────────────────────────────────────────────────────────
# 3. Run Select Events
# ─────────────────────────────────────────────────────────────
banner "3. Run Select Events"

section "QCR003 - SUID Binary Search" \
    "Searches for SUID/SGID binaries that could be used for privilege escalation"
run_cmd "${QCR}" events -event QCR003

section "QCR005 - Capability Check" \
    "Inspects Linux capabilities on the current process"
run_cmd "${QCR}" events -event QCR005

pause

section "QCR012 - Kubernetes Service Account Token Read" \
    "Attempts to read K8s service account tokens mounted in the container"
run_cmd "${QCR}" events -event QCR012

section "QCR016 - Network Port Scan" \
    "Scans common ports on localhost to detect listening services"
run_cmd "${QCR}" events -event QCR016

pause

section "QCR040 - Environment Variable Dump" \
    "Dumps environment variables (attackers look for secrets here)"
run_cmd "${QCR}" events -event QCR040

pause

# ─────────────────────────────────────────────────────────────
# 4. Run Events by Category
# ─────────────────────────────────────────────────────────────
banner "4. Run Events by Category"

section "Run all Credential Access events" \
    "Filters and runs events from a specific MITRE ATT&CK category"
run_cmd "${QCR}" events -all -category "Credential Access"

pause

# ─────────────────────────────────────────────────────────────
# 5. Drift Policy Management
# ─────────────────────────────────────────────────────────────
banner "5. Drift Policy Management"

section "List available drift policy types" \
    "Shows all policy types that can be generated"
run_cmd "${QCR}" drift list

DRIFT_DIR=$(mktemp -d)
trap 'rm -rf "${DRIFT_DIR}"' EXIT

section "Generate detect-mode policies" \
    "Creates Tetragon TracingPolicy YAML for drift detection"
run_cmd "${QCR}" drift generate -mode detect -output "${DRIFT_DIR}/detect"

section "Generated policy files" \
    "Showing the detect-mode policies that were created"
for f in "${DRIFT_DIR}/detect"/*.yaml; do
    if [ -f "$f" ]; then
        echo -e "${GREEN}--- $(basename "$f") ---${RESET}"
        cat "$f"
        echo ""
    fi
done

pause

section "Generate enforce-mode policies" \
    "Enforce mode blocks unauthorized binaries via Sigkill"
run_cmd "${QCR}" drift generate -mode enforce -output "${DRIFT_DIR}/enforce"

section "Generate lockdown-mode policies" \
    "Lockdown mode blocks binaries AND package managers"
run_cmd "${QCR}" drift generate -mode lockdown -output "${DRIFT_DIR}/lockdown"

pause

# ─────────────────────────────────────────────────────────────
# 6. CDR Policy Generation (optional)
# ─────────────────────────────────────────────────────────────
banner "6. CDR Policy Generation"

if [ -n "${QUALYS_ACCESS_TOKEN}" ] || { [ -n "${QUALYS_USERNAME}" ] && [ -n "${QUALYS_PASSWORD}" ]; }; then
    section "Fetch CDR findings" \
        "Pulls recent Container Detection & Response findings from Qualys"
    run_cmd "${QCR}" cdr fetch -hours 24 -limit 10

    section "Generate CDR-based policies" \
        "Converts CDR findings into Tetragon TracingPolicies"
    run_cmd "${QCR}" cdr policy -hours 24 -output "${DRIFT_DIR}/cdr"

    pause
else
    skip_msg "Set QUALYS_USERNAME/QUALYS_PASSWORD or QUALYS_ACCESS_TOKEN to enable CDR demo"
fi

# ─────────────────────────────────────────────────────────────
# 7. CBOM Scanning (optional)
# ─────────────────────────────────────────────────────────────
banner "7. Certificate BOM (CBOM) Scanning"

if command -v docker &>/dev/null || command -v kubectl &>/dev/null; then
    section "CBOM capabilities" \
        "Scans containers for TLS/SSL certificates and reports on expiration, key strength, etc."
    run_cmd "${QCR}" cbom --help
    pause
else
    skip_msg "Requires docker or kubectl to scan containers"
fi

# ─────────────────────────────────────────────────────────────
# 8. SBOM Generation (optional)
# ─────────────────────────────────────────────────────────────
banner "8. SBOM Generation"

section "SBOM capabilities" \
    "Generates Software Bills of Materials in CycloneDX or SPDX format"
run_cmd "${QCR}" sbom --help

pause

# ─────────────────────────────────────────────────────────────
# 9. AI Analysis (optional)
# ─────────────────────────────────────────────────────────────
banner "9. AI-Powered Analysis"

if [ -n "${ANTHROPIC_API_KEY}" ]; then
    section "AI CVE Explanation" \
        "Uses Claude to explain a CVE in plain English with remediation advice"
    run_cmd "${QCR}" ai explain -cve CVE-2024-21626

    pause
else
    skip_msg "Set ANTHROPIC_API_KEY to enable AI analysis demo"
fi

# ─────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────
banner "Demo Complete"
echo -e "  For more information, see the project README or run:"
echo -e "    ${GREEN}${QCR} help${RESET}"
echo ""
