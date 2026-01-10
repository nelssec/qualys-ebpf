#!/bin/bash
# Update threat intelligence feeds and regenerate blocklist policies
# Run this periodically (e.g., via CronJob) to keep blocklists current

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR_DIR="${SCRIPT_DIR}/../generator"
OUTPUT_DIR="${SCRIPT_DIR}/../policies/threat-intel"

echo "=========================================="
echo "Threat Intelligence Feed Update"
echo "=========================================="
echo ""

# Setup Python environment
if [ ! -d "${GENERATOR_DIR}/venv" ]; then
    echo "Setting up Python virtual environment..."
    python3 -m venv "${GENERATOR_DIR}/venv"
fi

source "${GENERATOR_DIR}/venv/bin/activate"
pip install -q requests pyyaml

# Run threat intel updater
echo "Fetching threat intelligence feeds..."
cd "${GENERATOR_DIR}"

# Pass API keys if available
ARGS="--output ${OUTPUT_DIR}"

if [ -n "$ABUSEIPDB_API_KEY" ]; then
    ARGS="${ARGS} --abuseipdb-key ${ABUSEIPDB_API_KEY}"
fi

if [ -n "$OTX_API_KEY" ]; then
    ARGS="${ARGS} --otx-key ${OTX_API_KEY}"
fi

python threat_intel.py ${ARGS}

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
