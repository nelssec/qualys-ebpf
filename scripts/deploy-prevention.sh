#!/bin/bash
# Deploy prevention policies (enforcement mode)
# WARNING: These policies will KILL processes that match the rules

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="${SCRIPT_DIR}/../policies/prevention"

echo "=========================================="
echo "WARNING: Prevention Policy Deployment"
echo "=========================================="
echo ""
echo "Prevention policies use Sigkill actions that will"
echo "terminate processes matching the policy rules."
echo ""
echo "This can disrupt legitimate workloads if policies"
echo "are not properly tuned for your environment."
echo ""
read -p "Do you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Deployment cancelled."
    exit 0
fi

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

# Apply all prevention policies
for policy in "${POLICIES_DIR}"/*.yaml; do
    if [ -f "$policy" ]; then
        echo "Applying: $(basename "$policy")"
        kubectl apply -f "$policy"
    fi
done

echo ""
echo "Prevention policies deployed successfully!"
echo "Monitor enforcement actions with: kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -f"
