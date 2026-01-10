#!/bin/bash
# Remove all deployed policies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCRIPT_DIR}/.."

echo "Removing all policies..."

# Remove TracingPolicies
echo "Removing TracingPolicies..."
for dir in detection prevention; do
    for policy in "${BASE_DIR}/policies/${dir}"/*.yaml; do
        if [ -f "$policy" ]; then
            echo "Removing: $(basename "$policy")"
            kubectl delete -f "$policy" --ignore-not-found=true
        fi
    done
done

# Remove FimPolicies
echo "Removing FimPolicies..."
for policy in "${BASE_DIR}/policies/fim"/*.yaml; do
    if [ -f "$policy" ]; then
        echo "Removing: $(basename "$policy")"
        kubectl delete -f "$policy" --ignore-not-found=true
    fi
done

echo ""
echo "All policies removed."
