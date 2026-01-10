# Qualys CDR Policy Operator

Enterprise-grade Kubernetes runtime security operator with AI-powered anomaly detection, multi-cluster federation, and comprehensive response capabilities.

## Features

### Core Capabilities
- **CDR Event Processing**: Fetches detection events and generates blocking policies
- **Dynamic IOC Extraction**: Extracts IPs, domains, ports from events
- **Threat Intel Integration**: Downloads and applies public threat feeds
- **IP Reputation Checking**: Validates IPs against AbuseIPDB and blocklists
- **Dual Policy Output**: Generates both Qualys TracingPolicies (syscall) and Qualys NetworkPolicies (CNI)

### Advanced Features
- **AI Anomaly Detection**: Isolation forest, k-means clustering, z-score, time series analysis
- **Behavioral Profiling**: 48hr learning period with anomaly scoring
- **Multi-Cluster Federation**: Hub-spoke architecture with cross-cluster correlation
- **Container Response Actions**: Kill, stop, pause, quarantine, forensics capture
- **Kubernetes Admission Controller**: Pre-deployment pod security validation
- **DNS Threat Monitoring**: DGA detection, malicious domain blocking
- **Attack Chain Correlation**: 7 built-in patterns with MITRE ATT&CK mapping
- **SIEM/SOAR Integrations**: Slack, PagerDuty, Teams, Splunk, Elasticsearch, Syslog

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           External Sources                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐ │
│  │  Qualys CDR API │  │  Threat Intel   │  │  Spoke Clusters (Events)    │ │
│  │  /cdr-api/rest  │  │  Feeds (5+)     │  │  Heartbeats, Detections     │ │
│  └────────┬────────┘  └────────┬────────┘  └──────────────┬──────────────┘ │
└───────────┼─────────────────────┼──────────────────────────┼────────────────┘
            │                     │                          │
            v                     v                          v
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Policy Operator                                      │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        Input Processing                               │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │  │
│  │  │ CDR Client   │  │ Threat Intel │  │ DNS Monitor  │  │ Admission │ │  │
│  │  │ Events       │  │ Reputation   │  │ DGA Detect   │  │ Webhook   │ │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘ │  │
│  └─────────┼─────────────────┼─────────────────┼────────────────┼───────┘  │
│            │                 │                 │                │          │
│            v                 v                 v                v          │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        Analysis Engine                                │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │  │
│  │  │ AI Detector  │  │ Behavioral   │  │ Correlation  │  │ Drift     │ │  │
│  │  │ - Isolation  │  │ Profiler     │  │ Engine       │  │ Detector  │ │  │
│  │  │   Forest     │  │ - Learning   │  │ - 7 Patterns │  │ - Exec    │ │  │
│  │  │ - K-Means    │  │ - Anomaly    │  │ - MITRE Map  │  │   Hashes  │ │  │
│  │  │ - Z-Score    │  │   Scoring    │  │ - Cross-     │  │ - Image   │ │  │
│  │  │ - Time Series│  │              │  │   Cluster    │  │   Baseline│ │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘ │  │
│  └─────────┼─────────────────┼─────────────────┼────────────────┼───────┘  │
│            │                 │                 │                │          │
│            v                 v                 v                v          │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        Response Engine                                │  │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌─────────┐ ┌───────┐ │  │
│  │  │ Kill   │ │ Stop   │ │ Pause  │ │Quarantine│ │Forensics│ │Network│ │  │
│  │  │Process │ │Container│ │Container│ │  File   │ │ Capture │ │Isolate│ │  │
│  │  └────────┘ └────────┘ └────────┘ └──────────┘ └─────────┘ └───────┘ │  │
│  └───────────────────────────────────┬──────────────────────────────────┘  │
│                                      │                                      │
│  ┌───────────────────────────────────┴──────────────────────────────────┐  │
│  │                        Output Layer                                   │  │
│  │  ┌───────┐ ┌─────────┐ ┌───────┐ ┌────────┐ ┌───────────┐ ┌────────┐ │  │
│  │  │ Slack │ │PagerDuty│ │ Teams │ │ Splunk │ │Elasticsearch│ │ Syslog │ │  │
│  │  └───────┘ └─────────┘ └───────┘ └────────┘ └───────────┘ └────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        Federation Manager                             │  │
│  │  Hub Mode: Policy Distribution, Event Aggregation, Cross-Cluster     │  │
│  │  Spoke Mode: Policy Sync, Event Forwarding, Heartbeat                │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       v
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                                   │
│  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────────────┐ │
│  │  TracingPolicy    │  │ NetworkPolicy      │  │  Federation CRDs       │ │
│  │  (Syscall-level)  │  │ (CNI-level)        │  │  FederatedCluster      │ │
│  │  - sys_execve     │  │ - egressDeny       │  │  FederatedTracingPolicy│ │
│  │  - sys_connect    │  │ - toCIDR           │  │  FederatedNetworkPolicy│ │
│  │  - sys_write      │  │ - toFQDNs          │  │                        │ │
│  └─────────┬─────────┘  └─────────┬─────────┘  └────────────────────────┘ │
│            │                      │                                        │
│            v                      v                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                    Qualys CRS Enforcement Layer                       │ │
│  │  - Syscall interception and blocking (Sigkill, Override)             │ │
│  │  - Network filtering (L3/L4/L7, FQDN blocking)                       │ │
│  │  - LSM hooks for persistent enforcement                              │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic Usage

```bash
# Set credentials
export QUALYS_USERNAME="your_username"
export QUALYS_PASSWORD="your_password"
export QUALYS_GATEWAY_URL="gateway.qg2.apps.qualys.com"

# Generate policies from CDR events
go run ./cmd/main.go --once --hours=24 --output=./policies

# With threat intel integration
go run ./cmd/main.go --once --threat-intel --output=./policies

# With IP reputation checking
export ABUSEIPDB_API_KEY="your_api_key"
go run ./cmd/main.go --once --threat-intel --reputation-threshold=50 --output=./policies
```

### Kubernetes Deployment

```bash
# Create namespace and credentials
kubectl create namespace qualys-system

kubectl create secret generic qualys-credentials \
  --from-literal=username=$QUALYS_USERNAME \
  --from-literal=password=$QUALYS_PASSWORD \
  -n qualys-system

# Optional: Add AbuseIPDB API key
kubectl create secret generic abuseipdb-credentials \
  --from-literal=api-key=$ABUSEIPDB_API_KEY \
  -n qualys-system

# Deploy CronJob
kubectl apply -f deploy/cronjob.yaml
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | - | Qualys platform (US1, US2, CA1, EU1, etc.) |
| `--gateway` | - | Gateway URL (overrides platform) |
| `--hours` | 24 | Lookback period for CDR events |
| `--action` | Post | Policy action: Post (audit) or Sigkill (block) |
| `--output` | ./policies | Output directory |
| `--apply` | false | Apply policies to cluster via kubectl |
| `--once` | false | Run once and exit (CronJob mode) |
| `--interval` | 1h | Update interval (controller mode) |
| `--threat-intel` | false | Enable threat intel feed integration |
| `--reputation-threshold` | 50 | Block IPs with score >= threshold |

## Generated Policies

### From CDR Events

| CDR Category | Generated Policy | Action |
|--------------|------------------|--------|
| Cloud_Credentials_Accessed | Block curl/wget to IMDS | Sigkill |
| Network_Scanning_Utility | Block nmap, raw sockets | Sigkill |
| Container_Escape | Block unshare, setns | Sigkill |
| Crypto_Mining | Block mining pool ports | Sigkill |

### From Threat Intel

| Feed | Type | Category |
|------|------|----------|
| Feodo Tracker | IP blocklist | C2 servers |
| Tor Exit Nodes | IP blocklist | Anonymization |
| Emerging Threats | IP blocklist | Compromised hosts |
| Blocklist.de | IP blocklist | Attackers |
| CINSscore | IP blocklist | Scanners |

### Output Files

```
policies/
├── cdr-block-cloud-creds-20260110.yaml     # Behavior policy
├── cdr-block-network-scan-20260110.yaml    # Behavior policy
├── cdr-dynamic-blocklist.yaml              # Extracted IOCs
├── qualys-cdr-blocklist.yaml               # Network policy
└── threat-intel-blocklist.yaml             # Known bad IPs
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `QUALYS_USERNAME` | Yes | Qualys API username |
| `QUALYS_PASSWORD` | Yes | Qualys API password |
| `QUALYS_GATEWAY_URL` | No | Gateway URL (default: US2) |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key for reputation |

## Threat Intelligence Feeds

The operator downloads and aggregates multiple threat intel feeds:

```go
feeds := []struct{
    name     string
    url      string
    category string
}{
    {"feodo-c2", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "c2"},
    {"tor-exit", "https://check.torproject.org/torbulkexitlist", "tor"},
    {"emerging-threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "compromised"},
    {"blocklist-de", "https://lists.blocklist.de/lists/all.txt", "attacker"},
    {"cinsscore", "https://cinsscore.com/list/ci-badguys.txt", "scanner"},
}
```

## Example Output

```
=== Policy Generation Run: 2026-01-10T16:45:00Z ===

Fetching CDR events (last 24 hours)...
Found 100 events

Event categories:
  Cloud_Credentials_Accessed_By_Network_Utility: 98
  Network_Scanning_Utility: 2

Generating behavior-based policies...
Generated 2 behavior policies
  Created: policies/cdr-block-cloud-creds-20260110.yaml
  Created: policies/cdr-block-network-scan-20260110.yaml

Extracting network indicators from events...
Extracted: 5 IPs, 0 domains, 2 ports
  Created: policies/cdr-dynamic-blocklist.yaml
  Created: policies/qualys-cdr-blocklist.yaml

Loading threat intelligence feeds...
Loaded 15234 IPs from feodo-c2
Loaded 1203 IPs from tor-exit
Loaded 8921 IPs from emerging-threats
Loaded 42156 IPs from blocklist-de
Loaded 3421 IPs from cinsscore
Known bad IPs: 70935
  Created: policies/threat-intel-blocklist.yaml

Done.
```

## Security Considerations

1. **Credentials**: Always use Kubernetes Secrets, never ConfigMaps
2. **Audit First**: Start with `--action=Post` before `--action=Sigkill`
3. **Review Policies**: Inspect generated policies before applying
4. **Rate Limits**: AbuseIPDB has API rate limits; use caching
5. **Policy Size**: Threat intel blocklists are capped at 1000 IPs

## Package Reference

### AI Anomaly Detection (`pkg/ai/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/ai"

// Create detector
config := ai.DefaultDetectorConfig()
detector := ai.NewAIDetector(config)

// Analyze features
anomalies := detector.Analyze(ctx, &ai.FeatureVector{
    Features: map[string]float64{
        "cpu_usage": 95.0,
        "syscalls":  1000,
    },
})

// Train models
detector.TrainIsolationForest(ctx)
detector.TrainClusters(ctx)
```

**Detection Methods:**
- **Z-Score**: Statistical deviation (threshold: 3.0)
- **IQR**: Interquartile range outliers
- **Isolation Forest**: Tree-based isolation scoring
- **K-Means**: Distance from cluster centroids
- **Time Series**: Moving average and trend analysis

### Behavioral Profiling (`pkg/behavior/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/behavior"

profiler := behavior.NewProfiler(48 * time.Hour)  // 48hr learning

// Process events
profiler.RecordProcess(containerID, processEvent)
profiler.RecordNetwork(containerID, networkEvent)
profiler.RecordFile(containerID, fileEvent)

// Check for anomalies
score, anomalies := profiler.CheckBehavior(containerID, event)
```

### Multi-Cluster Federation (`pkg/federation/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/federation"

// Hub cluster
hub := federation.NewFederationManager(&federation.Cluster{
    Role: federation.ClusterRoleHub,
})
hub.RegisterSpoke(spokeCluster)
hub.CreatePolicy(federatedPolicy)
hub.SyncPolicies(ctx)

// Spoke cluster
spoke := federation.NewFederationManager(&federation.Cluster{
    Role: federation.ClusterRoleSpoke,
})
spoke.ConnectToHub(hubEndpoint, token)
spoke.SendHeartbeat(ctx)
```

**Federation CRDs:**
- `FederatedCluster`: Spoke cluster registration
- `FederatedTracingPolicy`: Distributed TracingPolicy
- `FederatedNetworkPolicy`: Distributed Qualys NetworkPolicy

### Response Actions (`pkg/response/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/response"

executor := response.NewResponseExecutor()

// Execute actions
executor.KillProcess(pid)
executor.StopContainer(containerID)
executor.PauseContainer(containerID)
executor.QuarantineFile(filepath, destDir)
executor.CaptureForensics(containerID, outputDir)
executor.IsolateNetwork(namespace, podName)
```

### DNS Monitoring (`pkg/dns/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/dns"

monitor := dns.NewDNSMonitor(true)  // blocking enabled

// Load threat feeds
monitor.LoadThreatFeed(ctx, feedURL, "malware")

// Process queries
blocked, reason, threat := monitor.ProcessQuery(&dns.DNSQuery{
    QueryName: "malicious.example.com",
})

// Generate blocking policies
policy := monitor.GenerateDNSPolicy(blockedDomains)
```

### Correlation Engine (`pkg/correlation/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/correlation"

engine := correlation.NewCorrelationEngine()
engine.LoadDefaultPatterns()

// Process events
chains := engine.ProcessEvent(securityEvent)

// Check for attack chains
for _, chain := range chains {
    fmt.Printf("Attack: %s (confidence: %.2f)\n",
        chain.Type, chain.Confidence)
    fmt.Printf("MITRE: %v\n", chain.MitreTechniques)
}
```

**Built-in Attack Patterns:**
1. Container Breakout (T1611 → T1068 → T1059)
2. Cryptominer Deployment (T1105 → T1059 → T1496)
3. Credential Theft (T1552 → T1041)
4. Reverse Shell (T1071 → T1059.004)
5. Reconnaissance to Lateral Movement (T1046 → T1021)
6. Persistence Establishment (T1548 → T1053)
7. Defense Evasion Chain (T1070 → T1564)

### Admission Controller (`pkg/admission/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/admission"

controller := admission.NewAdmissionController()
controller.LoadDefaultPolicies()

// Add custom policy
controller.AddPolicy(&admission.AdmissionPolicy{
    Name:            "strict-security",
    BlockPrivileged: true,
    BlockHostNetwork: true,
    BlockedCapabilities: []string{"SYS_ADMIN", "SYS_PTRACE"},
})

// Start webhook server
controller.StartServer(ctx, ":8443", certFile, keyFile)
```

### Output Integrations (`pkg/outputs/`)

```go
import "github.com/qualys/qualys-ebpf/operator/pkg/outputs"

// Slack
slack := outputs.NewSlackOutput(webhookURL, "#security-alerts")
slack.Send(event)

// PagerDuty
pagerduty := outputs.NewPagerDutyOutput(routingKey)
pagerduty.Send(event)  // Only critical/high

// Splunk HEC
splunk := outputs.NewSplunkHECOutput(hecURL, token, "main", "qualys:crs")
splunk.Send(event)

// Elasticsearch
es := outputs.NewElasticsearchOutput(esURL, "security-events")
es.Send(event)
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `QUALYS_USERNAME` | Yes | Qualys API username |
| `QUALYS_PASSWORD` | Yes | Qualys API password |
| `QUALYS_GATEWAY_URL` | No | Gateway URL (default: US2) |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key |
| `SLACK_WEBHOOK_URL` | No | Slack webhook URL |
| `PAGERDUTY_ROUTING_KEY` | No | PagerDuty routing key |
| `SPLUNK_HEC_URL` | No | Splunk HEC endpoint |
| `SPLUNK_HEC_TOKEN` | No | Splunk HEC token |
| `ELASTICSEARCH_URL` | No | Elasticsearch endpoint |
| `FEDERATION_ROLE` | No | `hub` or `spoke` |
| `FEDERATION_HUB_URL` | No | Hub endpoint (spoke mode) |

## Testing & Benchmarks

Run unit tests and benchmarks:

```bash
go test ./pkg/... -v -cover
go test ./pkg/... -bench=. -benchmem
```

### Coverage

| Package | Coverage | Tests |
|---------|----------|-------|
| `pkg/ai` | 75.5% | 19 |
| `pkg/federation` | 46.6% | 24 |
| `pkg/response` | 60.4% | 28 |

### Key Benchmarks

| Operation | Performance | Memory |
|-----------|-------------|--------|
| AI Analyze | 27μs | 17KB |
| Isolation Forest Score | 5.7μs | 0B |
| K-Means Clustering | 1.6ms | 248KB |
| Cross-Cluster Correlation | 2.3μs | 2.5KB |
| Input Validation | 230-390ns | 0B |

## Prometheus Metrics

The operator exposes Prometheus metrics at `/metrics`:

```
# AI Detection
qualys_ai_anomalies_total
qualys_ai_containers_learning
qualys_ai_containers_ready

# Federation
qualys_federation_clusters_total
qualys_federation_clusters_healthy
qualys_federation_syncs_total
qualys_federation_syncs_failed

# Admission
qualys_admission_total
qualys_admission_allowed
qualys_admission_denied

# Response Actions
qualys_response_actions_total{action="kill|stop|pause|quarantine"}
qualys_response_actions_failed

# Correlation
qualys_correlation_chains_detected
qualys_correlation_events_processed
```
