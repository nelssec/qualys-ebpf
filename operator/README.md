# Qualys CDR Policy Operator

Automatically generates Tetragon TracingPolicies and Cilium NetworkPolicies from Qualys CDR events and threat intelligence feeds.

## Features

- **CDR Event Processing**: Fetches detection events and generates blocking policies
- **Dynamic IOC Extraction**: Extracts IPs, domains, ports from events
- **Threat Intel Integration**: Downloads and applies public threat feeds
- **IP Reputation Checking**: Validates IPs against AbuseIPDB and blocklists
- **Dual Policy Output**: Generates both Tetragon (syscall) and Cilium (network) policies

## Architecture

```
                                    ┌─────────────────────┐
                                    │   Threat Intel      │
                                    │   Feeds             │
                                    │   - Feodo Tracker   │
                                    │   - Tor Exit Nodes  │
                                    │   - Emerging Threats│
                                    │   - AbuseIPDB       │
                                    └──────────┬──────────┘
                                               │
┌─────────────────────┐                        │
│   Qualys CDR API    │                        │
│   /cdr-api/rest/v1  │                        │
└──────────┬──────────┘                        │
           │                                   │
           v                                   v
┌──────────────────────────────────────────────────────────┐
│                    Policy Operator                        │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────┐ │
│  │ CDR Client     │  │ Network        │  │ Reputation  │ │
│  │ - Fetch events │  │ Blocker        │  │ Checker     │ │
│  │ - Parse threats│  │ - Extract IOCs │  │ - Feed sync │ │
│  └───────┬────────┘  │ - Build lists  │  │ - IP lookup │ │
│          │           └───────┬────────┘  └──────┬──────┘ │
│          v                   v                  v         │
│  ┌────────────────────────────────────────────────────┐  │
│  │              Policy Generator                       │  │
│  │  - TracingPolicy (Tetragon)                        │  │
│  │  - CiliumNetworkPolicy                             │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
           │
           v
┌──────────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                      │
│  ┌────────────────────┐    ┌────────────────────┐        │
│  │  TracingPolicy     │    │  CiliumNetworkPolicy│        │
│  │  (sys_connect,     │    │  (egressDeny,       │        │
│  │   sys_execve)      │    │   toCIDR, toFQDNs)  │        │
│  └─────────┬──────────┘    └──────────┬─────────┘        │
│            │                          │                   │
│            v                          v                   │
│  ┌────────────────────────────────────────────────────┐  │
│  │              eBPF Enforcement                       │  │
│  │  Tetragon: Syscall blocking (Sigkill)              │  │
│  │  Cilium:   Network blocking (Drop)                 │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
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
├── cilium-cdr-blocklist.yaml               # Network policy
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
  Created: policies/cilium-cdr-blocklist.yaml

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
