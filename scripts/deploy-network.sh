#!/bin/bash
# Deploy network security policies
# Includes both Tetragon TracingPolicies and Cilium Network Policies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="${SCRIPT_DIR}/../policies/network"

echo "=========================================="
echo "Network Security Policy Deployment"
echo "=========================================="
echo ""
echo "This will deploy:"
echo "  - Tetragon TracingPolicies (syscall-level)"
echo "  - Cilium Network Policies (CNI-level)"
echo ""
echo "Some policies will BLOCK traffic. Review before deploying to production."
echo ""

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed"
    exit 1
fi

if ! kubectl cluster-info &> /dev/null; then
    echo "Error: Cannot connect to Kubernetes cluster"
    exit 1
fi

# Deployment options
PS3="Select deployment mode: "
options=("Detection only (audit)" "Prevention (blocking)" "Full (audit + blocking)" "Cancel")
select opt in "${options[@]}"
do
    case $opt in
        "Detection only (audit)")
            DEPLOY_MODE="detect"
            break
            ;;
        "Prevention (blocking)")
            DEPLOY_MODE="prevent"
            break
            ;;
        "Full (audit + blocking)")
            DEPLOY_MODE="full"
            break
            ;;
        "Cancel")
            echo "Deployment cancelled."
            exit 0
            ;;
        *) echo "Invalid option";;
    esac
done

echo ""
echo "Deploying network policies in ${DEPLOY_MODE} mode..."
echo ""

# Deploy Tetragon policies
echo "--- Tetragon TracingPolicies ---"

if [ "$DEPLOY_MODE" == "detect" ] || [ "$DEPLOY_MODE" == "full" ]; then
    echo "Applying detection policies..."
    kubectl apply -f "${POLICIES_DIR}/detect-dns-exfiltration.yaml"
    kubectl apply -f "${POLICIES_DIR}/detect-c2-beaconing.yaml"
    kubectl apply -f "${POLICIES_DIR}/detect-network-scanning.yaml"
fi

if [ "$DEPLOY_MODE" == "prevent" ] || [ "$DEPLOY_MODE" == "full" ]; then
    echo "Applying prevention policies..."
    kubectl apply -f "${POLICIES_DIR}/block-suspicious-outbound.yaml"
    kubectl apply -f "${POLICIES_DIR}/block-reverse-shell-connections.yaml"
    kubectl apply -f "${POLICIES_DIR}/block-data-exfiltration.yaml"
fi

# Deploy Cilium Network Policies
echo ""
echo "--- Cilium Network Policies ---"

if [ "$DEPLOY_MODE" == "prevent" ] || [ "$DEPLOY_MODE" == "full" ]; then
    echo ""
    read -p "Deploy Cilium Network Policies? (yes/no): " deploy_cilium

    if [ "$deploy_cilium" == "yes" ]; then
        echo "Applying Cilium policies..."

        # Check if Cilium is installed
        if kubectl get crd ciliumnetworkpolicies.cilium.io &> /dev/null; then
            kubectl apply -f "${POLICIES_DIR}/cilium-block-known-bad-ips.yaml"
            kubectl apply -f "${POLICIES_DIR}/cilium-block-lateral-movement.yaml"

            read -p "Apply default deny egress? (CAUTION - may break apps) (yes/no): " apply_deny
            if [ "$apply_deny" == "yes" ]; then
                kubectl apply -f "${POLICIES_DIR}/cilium-default-deny-egress.yaml"
                echo "Applied default deny - make sure to add explicit allows!"
            fi
        else
            echo "Warning: Cilium CRDs not found. Skipping Cilium policies."
            echo "Install Cilium CNI to use network policies."
        fi
    fi
fi

echo ""
echo "Network policies deployed successfully!"
echo ""
echo "Monitor events:"
echo "  Tetragon: kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -f"
echo "  Cilium:   cilium monitor --type drop"
