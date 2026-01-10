#!/bin/bash
# Deploy detection policies (audit mode)
# These policies log events without blocking

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="${SCRIPT_DIR}/../policies/detection"

echo "Deploying detection policies..."

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed or not in PATH"
    exit 1
fi

# Check cluster connectivity
if ! kubectl cluster-info &> /dev/null; then
    echo "Error: Cannot connect to Kubernetes cluster"
    exit 1
fi

# Check if Qualys CRS is installed
if ! kubectl get crd tracingpolicies.cilium.io &> /dev/null; then
    echo "Warning: TracingPolicy CRD not found. Is Qualys CRS installed?"
    echo "Install Qualys CRS sensor to use TracingPolicies."
fi

# Apply all detection policies
for policy in "${POLICIES_DIR}"/*.yaml; do
    if [ -f "$policy" ]; then
        echo "Applying: $(basename "$policy")"
        kubectl apply -f "$policy"
    fi
done

echo ""
echo "Detection policies deployed successfully!"
echo "View events with: kubectl logs -n kube-system -l app.kubernetes.io/name=qualys-crs -f"
