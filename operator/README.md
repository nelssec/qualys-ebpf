# Qualys CDR Policy Operator

Automatically generates Tetragon TracingPolicies from Qualys CDR (Cloud Detection and Response) events.

## How It Works

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Qualys CDR API │────>│   Operator   │────>│ TracingPolicies │
│   (Detections)  │     │  (Go/K8s)    │     │   (Tetragon)    │
└─────────────────┘     └──────────────┘     └─────────────────┘
                              │
                              v
                        ┌──────────┐
                        │ Cluster  │
                        │ Security │
                        └──────────┘
```

1. **Fetch**: Operator queries Qualys CDR API for recent detection events
2. **Analyze**: Groups events by threat category (IMDS access, network scanning, etc.)
3. **Generate**: Creates TracingPolicies to detect/block similar attacks
4. **Apply**: Deploys policies to cluster (optional)

## Supported Threat Categories

| CDR Category | MITRE ATT&CK | Generated Policy |
|--------------|--------------|------------------|
| Cloud_Credentials_Accessed_By_Network_Utility | T1552.005 | Block curl/wget to IMDS |
| Network_Scanning_Utility | T1046 | Block nmap, masscan, raw sockets |
| Container_Escape | T1611 | Block unshare, setns |
| Privilege_Escalation | T1548 | Block setuid(0) |
| Crypto_Mining | T1496 | Block mining pool ports |
| Reverse_Shell | T1059.004 | Block shell spawning |

## Quick Start

### Option 1: CLI (One-time generation)

```bash
# Set credentials
export QUALYS_USERNAME="your_username"
export QUALYS_PASSWORD="your_password"
export QUALYS_GATEWAY_URL="gateway.qg2.apps.qualys.com"

# Run generator
go run ./cmd/main.go --once --hours=24 --action=Post --output=./policies

# Review and apply
kubectl apply -f ./policies/
```

### Option 2: Kubernetes CronJob (Automated)

```bash
# 1. Create namespace and secret
kubectl create namespace qualys-system

kubectl create secret generic qualys-credentials \
  --from-literal=username=YOUR_USERNAME \
  --from-literal=password=YOUR_PASSWORD \
  -n qualys-system

# 2. Create config
kubectl create configmap qualys-config \
  --from-literal=QUALYS_PLATFORM=US2 \
  -n qualys-system

# 3. Build and push operator image
docker build -t your-registry/policy-operator:latest .
docker push your-registry/policy-operator:latest

# 4. Update image in cronjob.yaml and deploy
kubectl apply -f deploy/cronjob.yaml

# 5. Trigger manually to test
kubectl create job --from=cronjob/qualys-policy-generator test-run -n qualys-system
kubectl logs -f job/test-run -n qualys-system
```

### Option 3: Long-running Controller

```bash
# Run continuously with 1-hour interval
go run ./cmd/main.go --interval=1h --action=Sigkill --apply
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `QUALYS_USERNAME` | Qualys API username | Yes |
| `QUALYS_PASSWORD` | Qualys API password | Yes |
| `QUALYS_GATEWAY_URL` | Gateway URL (e.g., gateway.qg2.apps.qualys.com) | No |
| `QUALYS_PLATFORM` | Platform ID (US1, US2, CA1, etc.) | No |

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | - | Qualys platform (US1, US2, CA1, EU1, etc.) |
| `--gateway` | - | Gateway URL (overrides platform) |
| `--hours` | 24 | Lookback period for events |
| `--action` | Post | Policy action: Post (audit) or Sigkill (block) |
| `--output` | ./policies | Output directory |
| `--apply` | false | Apply policies directly to cluster |
| `--once` | false | Run once and exit |
| `--interval` | 1h | Interval between updates (controller mode) |

### Qualys Platforms

| Platform | Gateway URL |
|----------|-------------|
| US1 | gateway.qg1.apps.qualys.com |
| US2 | gateway.qg2.apps.qualys.com |
| US3 | gateway.qg3.apps.qualys.com |
| US4 | gateway.qg4.apps.qualys.com |
| EU1 | gateway.qg1.apps.qualys.eu |
| EU2 | gateway.qg2.apps.qualys.eu |
| CA1 | gateway.qg1.apps.qualys.ca |
| IN1 | gateway.qg1.apps.qualys.in |
| AE1 | gateway.qg1.apps.qualys.ae |
| UK1 | gateway.qg1.apps.qualys.co.uk |
| AU1 | gateway.qg1.apps.qualys.com.au |
| KSA1 | gateway.qg1.apps.qualysksa.com |

## Example Output

Given CDR events for "Cloud_Credentials_Accessed_By_Network_Utility":

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cdr-block-cloud-creds-20260110
  labels:
    generated-by: qualys-cdr-operator
    mitre.attack/technique: T1552.005
    policy.qualys.com/priority: critical
spec:
  kprobes:
    - call: sys_connect
      syscall: true
      args:
        - index: 1
          type: sockaddr
      selectors:
        - matchArgs:
            - index: 1
              operator: SAddr
              values: ["169.254.169.254"]
          matchBinaries:
            - operator: In
              values: ["/usr/bin/curl", "/usr/bin/wget"]
          matchActions:
            - action: Sigkill
```

## Security Notes

- Store credentials in Kubernetes Secrets, not ConfigMaps
- Use RBAC to limit who can read the qualys-credentials secret
- Generated policies should be reviewed before applying in production
- Start with `--action=Post` (audit) before switching to `--action=Sigkill` (block)
