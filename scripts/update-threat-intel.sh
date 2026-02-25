#!/bin/bash
# Update threat intelligence by fetching CDR findings and generating policies
#
# Requires Qualys credentials:
#   QUALYS_USERNAME + QUALYS_PASSWORD, or QUALYS_ACCESS_TOKEN
#   QUALYS_POD (e.g., us1, us2, eu1)
#
# Usage:
#   ./update-threat-intel.sh                  # fetch + generate policies
#   ./update-threat-intel.sh --apply          # also apply policies to cluster

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
QCR="${PROJECT_DIR}/eventgen/bin/qcr"
OUTPUT_DIR="${PROJECT_DIR}/policies/threat-intel"

# Build qcr if not present
if [ ! -x "${QCR}" ]; then
    echo "Building qcr binary..."
    (cd "${PROJECT_DIR}/eventgen" && make build)
fi

# Check for credentials
if [ -z "${QUALYS_ACCESS_TOKEN}" ] && { [ -z "${QUALYS_USERNAME}" ] || [ -z "${QUALYS_PASSWORD}" ]; }; then
    echo "Error: Qualys credentials required."
    echo "Set QUALYS_USERNAME and QUALYS_PASSWORD, or QUALYS_ACCESS_TOKEN"
    echo "Also set QUALYS_POD (e.g., us1, us2, eu1)"
    exit 1
fi

echo "=========================================="
echo "Threat Intelligence Feed Update"
echo "=========================================="
echo ""

# Fetch CDR findings
echo "Fetching CDR findings from Qualys..."
"${QCR}" cdr fetch -hours 24 -limit 100
echo ""

# Generate policies from findings
echo "Generating TracingPolicies from CDR findings..."
mkdir -p "${OUTPUT_DIR}"
"${QCR}" cdr policy -hours 24 -action Post -output "${OUTPUT_DIR}"
echo ""

echo "Policies generated in: ${OUTPUT_DIR}"

# Optionally apply to cluster
if [ "$1" == "--apply" ]; then
    echo ""
    echo "Applying updated policies to cluster..."

    if kubectl cluster-info &> /dev/null; then
        kubectl apply -f "${OUTPUT_DIR}/"
        echo "Policies applied successfully!"
    else
        echo "Error: Cannot connect to cluster. Policies saved but not applied."
    fi
else
    echo ""
    echo "To apply policies, run:"
    echo "  kubectl apply -f ${OUTPUT_DIR}/"
    echo ""
    echo "Or run this script with --apply flag"
fi
