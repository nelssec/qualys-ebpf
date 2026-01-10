#!/bin/bash
# Deploy FIM (File Integrity Monitoring) policies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="${SCRIPT_DIR}/../policies/fim"

echo "Deploying FIM policies..."

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

# Check if Qualys FimPolicy CRD is installed
if ! kubectl get crd fimpolicies.qualys.com &> /dev/null; then
    echo "Warning: FimPolicy CRD not found. Is Qualys CRS installed?"
    echo "Install Qualys CRS sensor with:"
    echo "  helm repo add qualys-helm-chart https://qualys.github.io/qualys_helm_charts/"
    echo "  helm install qualys-tc qualys-helm-chart/qualys-tc --set runtimeSensor.enabled=true -n qualys"
fi

# Apply all FIM policies
for policy in "${POLICIES_DIR}"/*.yaml; do
    if [ -f "$policy" ]; then
        echo "Applying: $(basename "$policy")"
        kubectl apply -f "$policy"
    fi
done

echo ""
echo "FIM policies deployed successfully!"
echo "View FIM policies: kubectl get fimpolicies.qualys.com"
