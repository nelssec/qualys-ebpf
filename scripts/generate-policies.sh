#!/bin/bash
# Generate drift detection/enforcement policies using the qcr CLI
#
# Usage:
#   ./generate-policies.sh                    # detect mode, all policies
#   ./generate-policies.sh -mode enforce      # enforce mode
#   ./generate-policies.sh -mode lockdown     # lockdown mode
#   ./generate-policies.sh -policy drift      # specific policy type
#   ./generate-policies.sh -namespace myns    # scoped to namespace

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
QCR="${PROJECT_DIR}/eventgen/bin/qcr"

# Build qcr if not present
if [ ! -x "${QCR}" ]; then
    echo "Building qcr binary..."
    (cd "${PROJECT_DIR}/eventgen" && make build)
fi

echo "=========================================="
echo "Qualys CRS - Drift Policy Generator"
echo "=========================================="
echo ""

# List available policy types
echo "Available policy types:"
"${QCR}" drift list
echo ""

# Generate policies (pass all arguments through)
echo "Generating policies..."
"${QCR}" drift generate "$@"

echo ""
echo "Done. Apply policies with:"
echo "  kubectl apply -f ./drift-policies/"
