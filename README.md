# Qualys eBPF Threat Detection & Prevention

Kubernetes CRDs and tooling for threat detection and prevention using Qualys Container Runtime Security (CRS) with Tetragon as the eBPF sensor.

## Overview

This repository provides:

- **Base TracingPolicy CRDs** for threat detection (audit mode)
- **Prevention TracingPolicy CRDs** for threat blocking (enforcement mode)
- **FimPolicy CRDs** for file integrity monitoring
- **Go operator** for automated policy generation from Qualys CDR events
- **Python generator** for policy creation and threat intel integration

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Qualys Cloud Platform                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  CDR API    │  │  CRS API    │  │  Threat Intelligence   │ │
│  │  Detections │  │  Runtime    │  │  IOCs, Vulnerabilities │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
└─────────┼────────────────┼─────────────────────┼───────────────┘
          │                │                     │
          v                v                     v
    ┌─────────────────────────────────────────────────┐
    │         Policy Operator (Go/Python)              │
    │  • Fetches CDR detection events                  │
    │  • Analyzes threat patterns                      │
    │  • Generates TracingPolicies                     │
    │  • Runs as CronJob or Controller                 │
    └─────────────────────────┬───────────────────────┘
                              │
                              v
    ┌─────────────────────────────────────────────────┐
    │            Kubernetes Cluster                    │
    │  ┌──────────────────┐  ┌──────────────────────┐ │
    │  │  TracingPolicies │  │  CiliumNetworkPolicy │ │
    │  │  (Tetragon)      │  │  (CNI-level)         │ │
    │  └────────┬─────────┘  └──────────┬───────────┘ │
    │           │                       │             │
    │           v                       v             │
    │  ┌────────────────────────────────────────────┐ │
    │  │          eBPF Enforcement                  │ │
    │  │  • Syscall interception (execve, connect) │ │
    │  │  • Network filtering (L3/L4/L7)           │ │
    │  │  • Process termination (Sigkill)          │ │
    │  └────────────────────────────────────────────┘ │
    └─────────────────────────────────────────────────┘
```

## Prerequisites

- Kubernetes cluster with Qualys CRS sensor installed
- kubectl configured for cluster access
- Python 3.8+ (for policy generator)

### Installing Qualys CRS

```bash
helm repo add qualys-helm-chart https://qualys.github.io/qualys_helm_charts/
helm repo update

helm install qualys-tc qualys-helm-chart/qualys-tc \
  --set global.customerId=YOUR_CUSTOMER_ID \
  --set global.activationId=YOUR_ACTIVATION_ID \
  --set global.gatewayUrl=YOUR_GATEWAY_URL \
  --set runtimeSensor.enabled=true \
  -n qualys --create-namespace
```

## Policy Types

### Detection Policies (Audit Mode)

Located in `policies/detection/`. These policies log suspicious activity without blocking:

| Policy | MITRE ATT&CK | Description |
|--------|--------------|-------------|
| reverse-shell-detection | T1059 | Monitors shell/scripting interpreter execution |
| privilege-escalation-detection | T1548 | Detects setuid/setgid and capability changes |
| container-escape-detection | T1611 | Monitors namespace manipulation, mounts |
| crypto-miner-detection | T1496 | Detects mining binaries and pool connections |
| lateral-movement-detection | T1021 | Monitors SSH, kubectl, and recon tools |
| credential-access-detection | T1552 | Monitors access to sensitive credential files |
| persistence-detection | T1053 | Monitors cron, systemd, and init.d changes |
| webshell-detection | T1505.003 | Detects shells spawned from web servers |

### Prevention Policies (Enforcement Mode)

Located in `policies/prevention/`. These policies KILL processes matching rules:

| Policy | Description |
|--------|-------------|
| block-container-escape | Blocks namespace manipulation and runtime socket access |
| block-crypto-miners | Kills known mining binaries and mining pool connections |
| block-reverse-shells | Blocks netcat/socat and shells from web servers |
| block-kernel-module-loading | Prevents kernel module loading |
| block-sensitive-file-writes | Blocks writes to /etc/passwd, shadow, cron, etc. |

### FIM Policies

Located in `policies/fim/`. File integrity monitoring using Qualys FimPolicy CRD:

| Policy | Description |
|--------|-------------|
| critical-system-files | Monitors /etc/passwd, shadow, sudoers |
| ssh-config-monitoring | Monitors SSH configuration and authorized_keys |
| persistence-paths | Monitors cron, systemd, init.d directories |
| kubernetes-secrets | Monitors K8s service account token access |
| web-directory-monitoring | Monitors web root directories |

### Network Security Policies

Located in `policies/network/`. Multi-layer network threat detection and blocking:

#### Tetragon TracingPolicies (Syscall-level)

| Policy | MITRE ATT&CK | Description |
|--------|--------------|-------------|
| block-suspicious-outbound | T1571 | Blocks C2/backdoor ports (4444, 6666, 31337, etc.) |
| block-reverse-shell-connections | T1059 | Blocks shells/netcat making outbound connections |
| detect-dns-exfiltration | T1048 | Monitors DNS traffic for data exfiltration |
| detect-network-scanning | T1046 | Detects port scanning and raw socket creation |
| detect-c2-beaconing | T1071 | Monitors HTTP/HTTPS for beacon patterns |
| block-data-exfiltration | T1041 | Blocks scp, ftp, rclone and exfil ports |

#### Cilium Network Policies (CNI-level)

| Policy | Description |
|--------|-------------|
| cilium-default-deny-egress | Default deny all egress (whitelist approach) |
| cilium-block-known-bad-ips | Block known malicious IPs/CIDRs |
| cilium-allow-essential-egress | Whitelist essential connectivity |
| cilium-block-lateral-movement | Prevent cross-namespace attacks, block metadata service |

## Quick Start

### Deploy Detection Policies

```bash
./scripts/deploy-detection.sh
```

### Deploy Prevention Policies (Caution!)

```bash
./scripts/deploy-prevention.sh
```

### Deploy FIM Policies

```bash
./scripts/deploy-fim.sh
```

### Deploy Network Security Policies

```bash
./scripts/deploy-network.sh
```

### Update Threat Intelligence Feeds

```bash
# Manual update
./scripts/update-threat-intel.sh

# Update and apply to cluster
./scripts/update-threat-intel.sh --apply

# Deploy CronJob for automatic updates
kubectl apply -f policies/network/threat-intel-cronjob.yaml
```

### Remove All Policies

```bash
./scripts/remove-all.sh
```

## Automated Policy Generation

### Option 1: Go Operator (Recommended for Production)

Deploy as a Kubernetes CronJob to automatically generate policies from CDR events:

```bash
# 1. Create namespace and credentials
kubectl create namespace qualys-system

kubectl create secret generic qualys-credentials \
  --from-literal=username=YOUR_USERNAME \
  --from-literal=password=YOUR_PASSWORD \
  -n qualys-system

kubectl create configmap qualys-config \
  --from-literal=QUALYS_PLATFORM=US2 \
  -n qualys-system

# 2. Deploy the operator
kubectl apply -f operator/deploy/cronjob.yaml

# 3. Trigger manually to test
kubectl create job --from=cronjob/qualys-policy-generator test-run -n qualys-system
```

See [operator/README.md](operator/README.md) for full documentation.

### Option 2: CLI (One-time or Local)

```bash
cd operator
go run ./cmd/main.go \
  --platform US2 \
  --hours 24 \
  --action Sigkill \
  --output ./policies
```

### Option 3: Python Generator

```bash
cd generator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Generate Base Policies

```bash
# Generate all policy types
python cli.py generate --type all --output ../generated-policies

# Generate only detection policies
python cli.py generate --type detection --output ../generated-policies

# Generate namespaced policies
python cli.py generate --type all --namespace my-namespace --output ../generated-policies
```

### Fetch from Qualys API

```bash
# Set credentials
export QUALYS_USERNAME=your_username
export QUALYS_PASSWORD=your_password
export QUALYS_API_URL=https://qualysapi.qualys.com

# Generate policies from Qualys threat data
python cli.py fetch --severity-min 4 --output ../qualys-policies

# Generate enforcement policies
python cli.py fetch --severity-min 5 --enforcement --output ../qualys-policies
```

### List Available Indicators

```bash
python cli.py list
python cli.py list --category crypto_miners
```

## TracingPolicy Structure

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: policy-name
  labels:
    threat.qualys.com/category: category
    mitre.attack/technique: T1234
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/malicious-binary"
      matchActions:
      - action: Post      # Audit mode
      # - action: Sigkill # Enforcement mode
```

## FimPolicy Structure

```yaml
apiVersion: qualys.com/v1
kind: FimPolicy
metadata:
  name: policy-name
spec:
  base-policy: "file-write"  # file-open, file-read, file-write, file-write-diff, file-rename, file-delete
  action: "audit"
  monitor-paths:
    - "/etc/passwd"
    - "/etc/shadow"
```

## Available Actions

| Action | Description |
|--------|-------------|
| Post | Log the event (audit mode) |
| Sigkill | Kill the process immediately |
| Signal | Send a specific signal |
| Override | Override syscall return value |

## Available Selectors

- `matchArgs` - Filter on syscall arguments
- `matchBinaries` - Filter on process binary path
- `matchPIDs` - Filter on process ID
- `matchNamespaces` - Filter on Linux namespaces
- `matchCapabilities` - Filter on capabilities
- `matchNamespaceChanges` - Detect namespace modifications
- `matchCapabilityChanges` - Detect capability changes

## Qualys API Integration

### Platform URLs

| Platform | URL |
|----------|-----|
| US Platform 1 | `qualysapi.qualys.com` |
| US Platform 2 | `qualysguard.qg2.apps.qualys.com` |
| US Platform 3 | `qualysguard.qg3.apps.qualys.com` |
| Canada | `qualysguard.qg1.apps.qualys.ca` |
| EU Platform 1 | `qualysguard.qualys.eu` |
| EU Platform 2 | `qualysguard.qg2.apps.qualys.eu` |
| India | `qualysguard.qg1.apps.qualys.in` |
| UAE | `qualysguard.qg1.apps.qualys.ae` |
| Australia | `qualysguard.qg1.apps.qualys.com.au` |

### API Endpoints

| API | Base Path | Description |
|-----|-----------|-------------|
| CDR | `/cloudview/rest/v1/cdr` | Cloud Detection & Response events |
| Container Security | `/csapi/v1.3` | Container runtime events |
| KnowledgeBase | `/api/2.0/fo/knowledge_base` | Vulnerability data |

### Generate Policies from CDR Events

```bash
# Set credentials
export QUALYS_USERNAME=your_username
export QUALYS_PASSWORD=your_password

# Generate from CDR detections (Canada platform)
python generator/cli.py cdr \
  --platform qualysguard.qg1.apps.qualys.ca \
  --hours 24 \
  --severity HIGH \
  --output ./cdr-policies

# Generate enforcement policies
python generator/cli.py cdr --action Sigkill --output ./cdr-enforcement
```

### Available APIs

1. **CDR (Cloud Detection & Response)** - Container detection events with MITRE mappings
2. **Container Security (CRS)** - Runtime events, behavioral baselines
3. **KnowledgeBase** - Vulnerability data with threat intelligence
4. **Threat Protection** - Real-Time Threat Indicators (RTIs)

## Threat Intelligence Integration

The framework integrates with multiple open threat intel feeds:

| Feed | Type | Description |
|------|------|-------------|
| Emerging Threats | IPs | Compromised hosts and botnet C2 |
| Feodo Tracker | IPs | Banking trojan C2 servers |
| Tor Exit Nodes | IPs | Tor anonymization network exits |
| URLhaus | URLs | Active malware distribution URLs |
| AbuseIPDB (API) | IPs | Crowdsourced malicious IP reports |
| AlienVault OTX (API) | Mixed | Community threat intelligence |

### Automated Updates

```bash
# Set optional API keys for premium feeds
export ABUSEIPDB_API_KEY=your_key
export OTX_API_KEY=your_key

# Generate blocklist policies from all feeds
python generator/threat_intel.py --output policies/threat-intel

# Deploy CronJob for daily updates
kubectl apply -f policies/network/threat-intel-cronjob.yaml
```

## Directory Structure

```
qualys-ebpf/
├── operator/                 # Go-based policy operator
│   ├── cmd/main.go          # CLI and controller entrypoint
│   ├── pkg/
│   │   ├── cdr/client.go    # Qualys CDR API client
│   │   └── policy/generator.go # Policy generation logic
│   ├── deploy/
│   │   ├── cronjob.yaml     # Kubernetes CronJob deployment
│   │   └── secret.yaml.example # Credentials template
│   ├── Dockerfile
│   └── README.md
├── policies/
│   ├── detection/           # Audit-mode TracingPolicies
│   ├── prevention/          # Enforcement-mode TracingPolicies
│   ├── fim/                 # FimPolicies
│   ├── network/             # Network security (Tetragon + Cilium)
│   └── library/             # Curated policies by maturity
│       ├── stable/          # Production-ready policies
│       ├── incubating/      # Robust but may need tuning
│       └── sandbox/         # Experimental policies
├── generator/               # Python generator (alternative)
│   ├── cli.py              # Command-line interface
│   ├── qualys_cdr_client.py # Qualys CDR/CS API client
│   ├── platforms.py        # Platform URL mapping
│   └── requirements.txt
├── scripts/
│   ├── deploy-detection.sh
│   ├── deploy-prevention.sh
│   └── remove-all.sh
└── README.md
```

## Policy Maturity Levels

Following [Falco's maturity framework](https://github.com/falcosecurity/rules):

| Level | Description |
|-------|-------------|
| **stable** | Production-ready, well-tested, low false positives |
| **incubating** | Robust but may need environment-specific tuning |
| **sandbox** | Experimental, may have higher false positive rates |

## Cilium Network Policy Structure

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: policy-name
spec:
  endpointSelector:
    matchLabels:
      app: myapp
  egress:
  - toFQDNs:
    - matchName: "api.example.com"
    toPorts:
    - ports:
      - port: "443"
  egressDeny:
  - toCIDR:
    - "10.0.0.0/8"  # Block internal ranges
```

## Network Match Operators (Tetragon)

| Operator | Description |
|----------|-------------|
| DPort | Destination port equals |
| NotDPort | Destination port not equals |
| DPortPriv | Destination port is privileged (<1024) |
| SPort | Source port equals |
| DAddr | Destination IP address |
| SAddr | Source IP address |
| Protocol | IP protocol (TCP, UDP, ICMP) |

## Best Practices Applied

This project follows best practices from:

- **[Falco Rules](https://github.com/falcosecurity/rules)** - CNCF graduated runtime security
- **[Tetragon Policy Library](https://tetragon.io/docs/policy-library/)** - Cilium's eBPF enforcement
- **[CrowdStrike Container Security](https://www.crowdstrike.com/products/cloud-security/)** - Similar detection patterns
- **MITRE ATT&CK Framework** - All policies tagged with techniques

Key practices:
- Maturity levels (stable/incubating/sandbox)
- MITRE ATT&CK technique tagging
- Priority levels (CRITICAL/HIGH/MEDIUM/LOW)
- False positive documentation
- Falco rule equivalents noted

## References

- [Qualys Container Runtime Security](https://docs.qualys.com/en/cs/crs-api/)
- [Qualys Container Security API](https://docs.qualys.com/en/cs/api/)
- [Qualys TotalCloud CDR](https://docs.qualys.com/en/cloudview/latest/cloud_detection_and_response/)
- [Tetragon TracingPolicy](https://tetragon.io/docs/concepts/tracing-policy/)
- [Tetragon Policy Library](https://tetragon.io/docs/policy-library/)
- [Cilium Network Policies](https://docs.cilium.io/en/stable/security/policy/)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Qualys API Documentation](https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf)
