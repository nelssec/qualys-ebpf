# Qualys Container Runtime Security

Enterprise-grade Kubernetes runtime security using Qualys Container Runtime Security (CRS). Provides real-time threat detection, prevention, and response with AI-powered anomaly detection and multi-cluster federation using Qualys TracingPolicies and Qualys NetworkPolicies.

## Overview

This repository provides:

- **49 CRS Detection Policies** mapped to MITRE ATT&CK techniques
- **Prevention TracingPolicy CRDs** for threat blocking (enforcement mode)
- **FimPolicy CRDs** for file integrity monitoring
- **Go operator** with real-time webhook, AI anomaly detection, and multi-cluster federation
- **Network Security Policies** for threat intel-based blocking
- **Kubernetes Admission Controller** for pre-deployment security

## Key Features

### Runtime Detection & Prevention
- **49 MITRE-mapped detection rules** covering persistence, privilege escalation, credential access, lateral movement, defense evasion, and more
- **Real-time process enforcement** via Sigkill, syscall override, and LSM hooks
- **Container response actions** including stop, pause, kill, quarantine, and network isolation
- **File integrity monitoring** for critical system and configuration files

### AI-Powered Security
- **Behavioral profiling** with configurable learning periods (default 48hr)
- **Statistical anomaly detection** using Z-score and IQR analysis
- **Time series analysis** with trend detection and moving averages
- **Isolation Forest ML algorithm** for unsupervised anomaly detection
- **K-means clustering** for behavioral grouping and outlier detection

### Multi-Cluster Federation
- **Hub-spoke architecture** for central policy management
- **Federated TracingPolicies** with per-cluster overrides
- **Cross-cluster event aggregation** and correlation
- **Coordinated attack detection** across multiple Kubernetes clusters
- **Kubernetes-native CRDs** for federation management

### Integrations
- **SIEM/SOAR outputs**: Slack, PagerDuty, Microsoft Teams, Splunk HEC, Elasticsearch, Syslog
- **Threat intelligence feeds**: 5+ IP reputation sources with auto-updates
- **DNS threat monitoring** with DGA detection and malicious domain blocking
- **Qualys CDR integration** for unified cloud/container detection

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Qualys Cloud Platform                              │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐                  │
│  │  CDR API    │  │  CRS API    │  │ Threat Intel     │                  │
│  │  Detections │  │  Runtime    │  │ IOCs, Feeds      │                  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬─────────┘                  │
└─────────┼────────────────┼──────────────────┼────────────────────────────┘
          │                │                  │
          v                v                  v
┌──────────────────────────────────────────────────────────────────────────┐
│                     Policy Operator (Go)                                  │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ CDR Client    │  │ AI Detector   │  │ Federation   │  │ Admission  │ │
│  │ - Events      │  │ - Isolation   │  │ Manager      │  │ Controller │ │
│  │ - Detections  │  │   Forest      │  │ - Hub/Spoke  │  │ - Pod      │ │
│  │               │  │ - Clustering  │  │ - Policy     │  │   Validation│ │
│  │               │  │ - Z-Score     │  │   Sync       │  │            │ │
│  └───────┬───────┘  └───────┬───────┘  └──────┬───────┘  └──────┬─────┘ │
│          │                  │                 │                 │        │
│  ┌───────┴──────────────────┴─────────────────┴─────────────────┴─────┐ │
│  │                        Response Engine                              │ │
│  │  Kill │ Stop │ Pause │ Quarantine │ Forensics │ Network Isolate    │ │
│  └───────────────────────────────────┬────────────────────────────────┘ │
│                                      │                                   │
│  ┌───────────────────────────────────┴────────────────────────────────┐ │
│  │                      Output Integrations                            │ │
│  │  Slack │ PagerDuty │ Teams │ Splunk │ Elasticsearch │ Syslog       │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────┬───────────────────────────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
          v                            v                            v
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  Cluster: Hub       │    │  Cluster: Spoke 1   │    │  Cluster: Spoke 2   │
│  ┌───────────────┐  │    │  ┌───────────────┐  │    │  ┌───────────────┐  │
│  │TracingPolicy  │  │    │  │TracingPolicy  │  │    │  │TracingPolicy  │  │
│  │NetworkPolicy  │  │    │  │NetworkPolicy  │  │    │  │NetworkPolicy  │  │
│  │FederatedCRDs  │  │    │  │(Synced)       │  │    │  │(Synced)       │  │
│  └───────┬───────┘  │    │  └───────┬───────┘  │    │  └───────┬───────┘  │
│          v          │    │          v          │    │          v          │
│  ┌───────────────┐  │    │  ┌───────────────┐  │    │  ┌───────────────┐  │
│  │eBPF Enforce   │  │    │  │eBPF Enforce   │  │    │  │eBPF Enforce   │  │
│  │Qualys Runtime │  │    │  │Qualys Runtime │  │    │  │Qualys Runtime │  │
│  └───────────────┘  │    │  └───────────────┘  │    │  └───────────────┘  │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## QCR CLI Tool (v1.0.3)

A single Go binary for CDR integration, policy generation, and drift enforcement.

### Installation

```bash
# Build from source
cd eventgen && make build

# Or download pre-built binary
curl -LO https://github.com/qualys/qualys-ebpf/releases/latest/download/qcr-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
chmod +x qcr-* && mv qcr-* /usr/local/bin/qcr
```

### CDR Policy Generation

Generate TracingPolicies from live Qualys CDR findings:

```bash
# Set credentials
export QUALYS_USERNAME=your_username
export QUALYS_PASSWORD=your_password
export QUALYS_POD=us2  # us1, us2, eu1, eu2, in1, etc.

# Fetch CDR findings
qcr cdr fetch --hours 24

# Generate policies from findings (audit mode)
qcr cdr policy --hours 24 --action Post --output ./cdr-policies

# Generate enforcement policies with namespace scoping
qcr cdr policy --hours 24 --action Sigkill --namespace production --output ./cdr-policies

# Generate with pod label selectors
qcr cdr policy --hours 24 --action Sigkill --selector "app=nginx,tier=frontend" --output ./cdr-policies
```

Supported CDR threat categories with specific MITRE mappings:
- **Crypto Mining** (T1496) - Blocks mining pool ports (3333, 4444, 14433, etc.)
- **SSH Brute Force** (T1110.001) - Monitors SSH authentication events
- **Port Scanning** (T1046) - Detects network reconnaissance
- **Container Escape** (T1611) - Blocks namespace manipulation and runtime sockets
- **Credential Access** (T1552) - Monitors sensitive file access
- **Trojan/Malware** (T1204) - Blocks execution from /tmp, /var/tmp, /dev/shm

### Drift Detection & Lockdown

Enforce container immutability with drift detection policies:

```bash
# List available drift policies
qcr drift list

# Generate basic drift policy (block new executables)
qcr drift generate --output ./drift-policies

# Generate full lockdown mode (8 policies)
qcr drift lockdown --action Sigkill --namespace production --output ./lockdown-policies
```

Lockdown policies include:
- **Basic Drift** - Block execution of new binaries not in original image
- **Tmp Exec Block** - Block execution from /tmp, /var/tmp, /dev/shm
- **Script Interpreter Lockdown** - Block python/perl/ruby spawning shells
- **Memory Execution Block** - Block memfd_create (fileless malware)
- **Chmod Block** - Block chmod +x on any file
- **Reverse Shell Block** - Block common reverse shell patterns
- **Network Tool Block** - Block netcat, nmap, curl to suspicious ports
- **Container Tools Block** - Block docker/kubectl/crictl inside containers

### Vulnerability Correlation

Correlate runtime events with container vulnerabilities:

```bash
# Fetch vulnerabilities
qcr vulns fetch --severity-min 4 --output ./vulns.json

# Correlate with CDR events
qcr vulns correlate --hours 24 --output ./correlations.json

# Analytics (Pareto analysis - top vulns fixing 80% of issues)
qcr vulns analytics --pareto --top 10

# Export for external scripts
qcr vulns export --format json --output ./vuln-data.json
```

### AI-Powered Analysis

```bash
# Analyze recent events with AI
qcr ai analyze --hours 24
```

## Prerequisites

- Kubernetes cluster with Qualys CRS sensor installed
- kubectl configured for cluster access
- Go 1.24+ (for building qcr from source)

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

### CRS Detection Policies (49 Rules)

Located in `policies/crs-detections/`. Comprehensive detection coverage mapped to MITRE ATT&CK:

| Category | Rules | MITRE Tactics | Key Detections |
|----------|-------|---------------|----------------|
| **Persistence** | 8 | TA0003 | Cron jobs, systemd services, init scripts, kernel modules |
| **Privilege Escalation** | 10 | TA0004 | Setuid/setgid, sudo abuse, capability changes, DAC bypass |
| **Credential Access** | 6 | TA0006 | /etc/shadow, SSH keys, cloud credentials, service accounts |
| **Defense Evasion** | 7 | TA0005 | Log tampering, timestomping, masquerading, rootkits |
| **Lateral Movement** | 4 | TA0008 | SSH, kubectl exec, network scanning, port forwarding |
| **Execution** | 5 | TA0002 | Reverse shells, script interpreters, container exec |
| **Collection** | 3 | TA0009 | Data staging, archive creation, sensitive file access |
| **Command & Control** | 3 | TA0011 | DNS tunneling, unusual ports, encrypted channels |
| **Exfiltration** | 3 | TA0010 | Data transfer, cloud storage, encoding |

Deploy with Kustomize overlays for different environments:

```bash
# Development (audit only)
kubectl apply -k policies/crs-detections/kustomize/overlays/dev

# Staging (selective enforcement)
kubectl apply -k policies/crs-detections/kustomize/overlays/staging

# Production (full enforcement)
kubectl apply -k policies/crs-detections/kustomize/overlays/prod
```

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

#### Qualys TracingPolicies (Syscall-level)

| Policy | MITRE ATT&CK | Description |
|--------|--------------|-------------|
| block-suspicious-outbound | T1571 | Blocks C2/backdoor ports (4444, 6666, 31337, etc.) |
| block-reverse-shell-connections | T1059 | Blocks shells/netcat making outbound connections |
| detect-dns-exfiltration | T1048 | Monitors DNS traffic for data exfiltration |
| detect-network-scanning | T1046 | Detects port scanning and raw socket creation |
| detect-c2-beaconing | T1071 | Monitors HTTP/HTTPS for beacon patterns |
| block-data-exfiltration | T1041 | Blocks scp, ftp, rclone and exfil ports |

#### Qualys Network Policies (CNI-level)

| Policy | Description |
|--------|-------------|
| qualys-default-deny-egress | Default deny all egress (whitelist approach) |
| qualys-block-known-bad-ips | Block known malicious IPs/CIDRs |
| qualys-allow-essential-egress | Whitelist essential connectivity |
| qualys-block-lateral-movement | Prevent cross-namespace attacks, block metadata service |

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

# 2. Deploy the CronJob
kubectl apply -f eventgen/deploy/cronjob.yaml

# 3. Trigger manually to test
kubectl create job --from=cronjob/qualys-policy-generator test-run -n qualys-system
```

### Option 2: CLI (One-time or Local)

```bash
cd eventgen
qcr cdr policy --hours 24 --action Sigkill --output ./policies
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
export QUALYS_POD=ca1  # Canada platform

# Generate from CDR detections
qcr cdr policy --hours 24 --output ./cdr-policies

# Generate enforcement policies
qcr cdr policy --action Sigkill --output ./cdr-enforcement
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
# Deploy CronJob for daily threat intel updates
kubectl apply -f policies/network/threat-intel-cronjob.yaml
```

## Directory Structure

```
qualys-ebpf/
├── eventgen/                      # Go CLI tool (qcr) - unified binary
│   ├── cmd/main.go               # CLI entrypoint
│   ├── pkg/
│   │   ├── ai/                   # AI anomaly detection (Isolation Forest, K-means)
│   │   ├── analytics/            # Vulnerability analytics
│   │   ├── behavior/             # Behavioral profiling with learning
│   │   ├── correlation/          # Attack chain correlation (7 MITRE patterns)
│   │   ├── dns/                  # DNS monitoring, DGA detection
│   │   ├── drift/                # Drift detection and lockdown policies
│   │   ├── events/               # Security event catalog for testing
│   │   ├── federation/           # Multi-cluster hub-spoke federation
│   │   ├── network/              # Network IOC extraction and blocking
│   │   ├── outputs/              # SIEM integrations (Slack, Splunk, etc.)
│   │   ├── policy/               # TracingPolicy generator
│   │   ├── qualys/               # Qualys CDR/CS API client
│   │   ├── reputation/           # IP reputation checking
│   │   ├── response/             # Response actions (kill, stop, quarantine)
│   │   ├── vuln/                 # Vulnerability correlation
│   │   └── webhook/              # Event webhook server
│   ├── deploy/
│   │   └── cronjob.yaml         # Kubernetes CronJob deployment
│   ├── Dockerfile               # Multi-stage container build
│   └── Makefile
├── policies/
│   ├── crs-detections/          # 49 CRS detection rules
│   │   ├── generated/           # Auto-generated YAML policies
│   │   ├── kustomize/           # Kustomize overlays
│   │   │   ├── base/            # Base policies
│   │   │   └── overlays/        # Environment-specific
│   │   │       ├── dev/         # Development (audit only)
│   │   │       ├── staging/     # Staging (selective enforcement)
│   │   │       └── prod/        # Production (full enforcement)
│   │   └── README.md
│   ├── detection/               # Audit-mode TracingPolicies
│   ├── prevention/              # Enforcement-mode TracingPolicies
│   ├── fim/                     # FimPolicies
│   ├── network/                 # Network security (Qualys TracingPolicy + NetworkPolicy)
│   │   ├── block-imds.yaml             # Block cloud metadata service
│   │   ├── block-crypto-mining-pools.yaml
│   │   ├── block-reverse-shell-ports.yaml
│   │   ├── block-tor-exit-nodes.yaml
│   │   └── block-dns-over-https.yaml
│   └── library/                 # Curated policies by maturity
│       ├── stable/              # Production-ready policies
│       ├── incubating/          # Robust but may need tuning
│       └── sandbox/             # Experimental policies
├── scripts/
│   ├── deploy-detection.sh
│   ├── deploy-prevention.sh
│   └── remove-all.sh
└── README.md
```

## Operator Components

### AI-Powered Anomaly Detection

The AI detector (`pkg/ai/detector.go`) provides multiple anomaly detection algorithms:

```go
// Create detector with configuration
config := ai.DefaultDetectorConfig()
config.LearningPeriod = 48 * time.Hour
config.ZScoreThreshold = 3.0
detector := ai.NewAIDetector(config)

// Analyze feature vectors
anomalies := detector.Analyze(ctx, &ai.FeatureVector{
    Timestamp:     time.Now(),
    ContainerID:   "abc123",
    ContainerName: "web-app",
    Features: map[string]float64{
        "cpu_usage":     85.0,
        "memory_usage":  92.0,
        "network_bytes": 1500000,
        "syscall_rate":  500,
    },
})

// Train models periodically
detector.TrainIsolationForest(ctx)
detector.TrainClusters(ctx)
```

**Detection Methods:**
| Method | Description | Use Case |
|--------|-------------|----------|
| Z-Score | Statistical deviation from mean | Sudden spikes |
| IQR | Interquartile range outliers | Robust to extreme values |
| Time Series | Moving average deviation, trend detection | Behavioral drift |
| Isolation Forest | Tree-based anomaly isolation | Multi-dimensional anomalies |
| K-Means Clustering | Distance from cluster centroids | Behavioral grouping |

### Multi-Cluster Federation

The federation manager (`pkg/federation/manager.go`) enables central policy management:

```yaml
# Register spoke cluster
apiVersion: federation.qualys.com/v1alpha1
kind: FederatedCluster
metadata:
  name: prod-us-east
  labels:
    environment: production
    region: us-east
spec:
  endpoint: https://prod-us-east.k8s.example.com:6443
  region: us-east-1
  provider: aws
  secretRef:
    name: spoke-cluster-credentials
    namespace: qualys-system
```

```yaml
# Distribute policy to all production clusters
apiVersion: federation.qualys.com/v1alpha1
kind: FederatedTracingPolicy
metadata:
  name: detect-cryptominer-global
spec:
  template:
    metadata:
      name: crs-detect-cryptominer
    spec:
      kprobes:
        - call: sys_execve
          syscall: true
          # ... policy spec
  placement:
    clusterSelector:
      matchLabels:
        environment: production
  overrides:
    - clusterName: prod-eu
      patches:
        - op: replace
          path: /spec/kprobes/0/selectors/0/matchActions
          value:
            - action: Post  # Audit only in EU
```

**Cross-Cluster Attack Detection:**
- Coordinated attacks (same attack across multiple clusters)
- Lateral movement (reconnaissance → exploitation across clusters)
- Supply chain indicators (cryptominer in multiple clusters)

### Response Actions

The response engine (`pkg/response/actions.go`) provides multiple response options:

| Action | Description | Use Case |
|--------|-------------|----------|
| `ProcessKill` | SIGKILL to process | Immediate threat termination |
| `ContainerKill` | Force remove container | Compromised container |
| `ContainerStop` | Graceful container stop | Suspicious but uncertain |
| `ContainerPause` | Suspend all processes | Forensic preservation |
| `FileQuarantine` | Compress and isolate file | Malware isolation |
| `ForensicsCapture` | Collect process info, logs | Incident response |
| `NetworkIsolate` | Create deny-all NetworkPolicy | Contain lateral movement |
| `LabelPod` | Add security labels | Tracking and alerting |

### Admission Controller

The admission controller (`pkg/admission/controller.go`) validates pods before deployment:

```yaml
# Default security policy
blockPrivileged: true
blockHostNetwork: true
blockHostPID: true
blockHostIPC: true
blockedCapabilities:
  - SYS_ADMIN
  - SYS_PTRACE
  - SYS_MODULE
  - NET_ADMIN
  - NET_RAW
blockHostPath: true
blockDockerSocket: true
```

### Output Integrations

The integrations module (`pkg/outputs/integrations.go`) supports multiple outputs:

| Output | Format | Severity Routing |
|--------|--------|------------------|
| Slack | Rich formatted messages | Color-coded by severity |
| PagerDuty | Incidents | Critical/High only |
| Microsoft Teams | MessageCard | All severities |
| Splunk HEC | JSON events | All severities |
| Elasticsearch | Documents | All severities |
| Syslog | CEF format | All severities |
| Generic Webhook | JSON POST | Configurable |

## Policy Maturity Levels

Following [Falco's maturity framework](https://github.com/falcosecurity/rules):

| Level | Description |
|-------|-------------|
| **stable** | Production-ready, well-tested, low false positives |
| **incubating** | Robust but may need environment-specific tuning |
| **sandbox** | Experimental, may have higher false positive rates |

## Qualys Network Policy Structure

```yaml
# Compatible with standard CNI NetworkPolicy spec
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

## Network Match Operators (Qualys TracingPolicy)

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
- **[Qualys TracingPolicy Library](policies/library/)** - eBPF enforcement policies
- **[CrowdStrike Container Security](https://www.crowdstrike.com/products/cloud-security/)** - Similar detection patterns
- **MITRE ATT&CK Framework** - All policies tagged with techniques

Key practices:
- Maturity levels (stable/incubating/sandbox)
- MITRE ATT&CK technique tagging
- Priority levels (CRITICAL/HIGH/MEDIUM/LOW)
- False positive documentation
- Falco rule equivalents noted

## Testing & Benchmarks

The operator includes comprehensive unit tests and benchmarks for critical components:

### Test Coverage

| Package | Coverage | Tests |
|---------|----------|-------|
| `pkg/ai` | 75.5% | 19 |
| `pkg/federation` | 46.6% | 24 |
| `pkg/response` | 60.4% | 28 |

### Performance Benchmarks (Apple M4)

| Operation | ns/op | Allocations |
|-----------|-------|-------------|
| AI Analyze | 27,179 | 31 allocs |
| Statistical Detection | 23,589 | 2 allocs |
| Isolation Forest Score | 5,679 | 0 allocs |
| Input Validation | 230-390 | 0 allocs |
| Policy Hash | 519 | 12 allocs |

Run tests and benchmarks:
```bash
cd operator
go test ./pkg/... -v
go test ./pkg/... -bench=. -benchmem
```

## References

- [Qualys Container Runtime Security](https://docs.qualys.com/en/cs/crs-api/)
- [Qualys Container Security API](https://docs.qualys.com/en/cs/api/)
- [Qualys TotalCloud CDR](https://docs.qualys.com/en/cloudview/latest/cloud_detection_and_response/)
- [Qualys TracingPolicy Reference](policies/library/)
- [Qualys NetworkPolicy Reference](policies/network/)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Qualys API Documentation](https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf)
