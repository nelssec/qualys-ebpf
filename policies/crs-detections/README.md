# Qualys CRS Detection Policies

Auto-generated Qualys TracingPolicies based on Qualys Container Runtime Security (CRS) detection rules.

## Overview

This directory contains **49 detection rules** mapped to MITRE ATT&CK techniques, organized by enforcement mode:

| Directory | Action | Use Case |
|-----------|--------|----------|
| `detection/` | Post (audit) | Monitor and alert only |
| `prevention/` | Sigkill (block) | Terminate malicious processes |
| `network/` | Qualys NetworkPolicy | Block malicious network traffic |
| `namespaced/` | Namespace-scoped | Pre-built compliance bundles |
| `kustomize/` | Environment overlays | Deploy by environment |

## Quick Start

### Deploy All Detection Policies (Audit Mode)

```bash
kubectl apply -f detection/
```

### Deploy All Prevention Policies (Enforcement Mode)

```bash
kubectl apply -f prevention/
```

### Deploy Using Kustomize

```bash
# Development (audit only)
kubectl apply -k kustomize/overlays/dev

# Staging (selective enforcement)
kubectl apply -k kustomize/overlays/staging

# Production (full enforcement)
kubectl apply -k kustomize/overlays/prod
```

## Coverage by MITRE ATT&CK Tactic

| Tactic | Rules | Key Detections |
|--------|-------|----------------|
| **Privilege Escalation** | 15 | Container escape, SUID abuse, capability exploitation |
| **Defense Evasion** | 8 | Log clearing, process hiding, rootkits |
| **Execution** | 7 | Reverse shells, miners, suspicious scripts |
| **Credential Access** | 4 | IMDS access, credential file theft |
| **Persistence** | 4 | Cron jobs, account modification |
| **Discovery** | 3 | Network scanning, capability enumeration |
| **Collection** | 2 | Data harvesting, traffic capture |
| **Command & Control** | 2 | SOCKS proxy, file transfers |
| **Lateral Movement** | 2 | SSH/SCP, database exploitation |
| **Impact** | 1 | Cryptomining |
| **Initial Access** | 1 | Exploit detection |

## Severity Distribution

- **Critical**: 20 rules (container escape, miners, privesc)
- **High**: 22 rules (credential theft, network scanning)
- **Medium**: 7 rules (shell spawning, package managers)

## Policy Structure

Each policy includes:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: crs-<detection-name>
  labels:
    generated-by: qualys-crs
    qualys.com/rule-id: <original-rule-id>
    mitre.attack/technique: T<xxxx>
    mitre.attack/tactic: <tactic>
    policy.qualys.com/severity: <critical|high|medium>
spec:
  kprobes:
    - call: <syscall>
      # ... detection logic
```

## Network Policies

Complementary Qualys NetworkPolicies for network-level blocking:

| Policy | Blocks |
|--------|--------|
| `block-imds.yaml` | Cloud metadata service (169.254.169.254) |
| `block-crypto-mining-pools.yaml` | Common mining pool ports |
| `block-reverse-shell-ports.yaml` | C2 and reverse shell ports |
| `block-tor-exit-nodes.yaml` | Tor network ports |
| `block-dns-over-https.yaml` | DoH providers (anti-evasion) |

## Namespace-Scoped Policies

Pre-built policy bundles for specific compliance requirements:

- **high-security-namespace.yaml**: Maximum protection for sensitive workloads
- **pci-compliant-namespace.yaml**: PCI-DSS aligned controls

## Regenerating Policies

```bash
# Activate virtual environment
source ../../generator/venv/bin/activate

# Regenerate all policies
python3 generate-all.py
```

## Integration with Qualys CDR

These policies integrate with the Qualys CDR Policy Operator:

1. CDR detects threats via API polling or webhooks
2. Operator generates corresponding TracingPolicies
3. Qualys CRS enforces policies at kernel level

See `/operator/` for the Go-based operator implementation.

## References

- [Qualys TracingPolicy Reference](../library/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Qualys CRS Documentation](https://www.qualys.com/docs/qualys-container-security-user-guide.pdf)
