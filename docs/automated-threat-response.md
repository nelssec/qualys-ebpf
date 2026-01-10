# Automating Container Threat Response with Qualys CDR

Detecting threats is only half the battle. The real challenge is responding to them fast enough to prevent damage. This guide explores how to create an automated feedback loop between Qualys Cloud Detection & Response (CDR) and Qualys CRS enforcement to automatically generate and deploy enforcement policies based on detected threats.

## The Problem: Detection Without Response

Traditional security monitoring creates a gap between detection and response:

```mermaid
sequenceDiagram
    participant Attacker
    participant Container
    participant Qualys CDR
    participant Security Team
    participant Policy

    Attacker->>Container: Execute attack
    Container->>Qualys CDR: Detection event
    Qualys CDR->>Security Team: Alert
    Note over Security Team: Manual analysis (hours/days)
    Security Team->>Policy: Create blocking rule
    Policy->>Container: Prevention enabled
    Note over Attacker: Already exfiltrated data
```

By the time security teams analyze alerts and create policies, attackers have often achieved their objectives.

## The Solution: Automated Policy Generation

This project closes the loop by automatically generating Qualys TracingPolicies from CDR detection events:

```mermaid
sequenceDiagram
    participant Attacker
    participant Container
    participant Qualys CDR
    participant Policy Operator
    participant Qualys CRS

    Attacker->>Container: Execute attack
    Container->>Qualys CDR: Detection event
    Qualys CDR->>Policy Operator: CDR API (hourly poll)
    Policy Operator->>Policy Operator: Analyze & generate policy
    Policy Operator->>Qualys CRS: Apply TracingPolicy
    Attacker->>Container: Repeat attack
    Qualys CRS->>Attacker: Process killed (Sigkill)
```

## Architecture Overview

The system consists of three main components working together:

```mermaid
flowchart TB
    subgraph Qualys["Qualys Cloud Platform"]
        CDR["CDR API<br/>/cdr-api/rest/v1/findings"]
        CRS["Container Runtime<br/>Security Sensor"]
    end

    subgraph K8s["Kubernetes Cluster"]
        subgraph Operator["Policy Operator"]
            Fetch["Fetch Events"]
            Analyze["Analyze Patterns"]
            Generate["Generate Policies"]
        end

        subgraph Enforcement["Qualys Enforcement Layer"]
            TracingPolicy["TracingPolicy<br/>(eBPF)"]
            NetworkPolicy["NetworkPolicy<br/>(CNI)"]
        end

        Workloads["Protected Workloads"]
    end

    CRS -->|Runtime Events| CDR
    CDR -->|API| Fetch
    Fetch --> Analyze
    Analyze --> Generate
    Generate -->|TracingPolicy| TracingPolicy
    Generate -->|NetworkPolicy| NetworkPolicy
    TracingPolicy -->|Syscall Enforcement| Workloads
    NetworkPolicy -->|Network Enforcement| Workloads
```

## Threat Categories and Responses

The operator maps CDR threat categories to specific enforcement actions:

```mermaid
flowchart LR
    subgraph Detection["CDR Detection"]
        D1["Cloud Credentials<br/>Accessed"]
        D2["Network Scanning<br/>Utility"]
        D3["Container Escape<br/>Attempt"]
        D4["Crypto Mining<br/>Activity"]
    end

    subgraph Policy["Generated Policy"]
        P1["Block curl/wget<br/>to IMDS"]
        P2["Block nmap,<br/>raw sockets"]
        P3["Block unshare,<br/>setns syscalls"]
        P4["Block mining<br/>pool ports"]
    end

    subgraph Action["Enforcement"]
        A1["Sigkill"]
        A2["Sigkill"]
        A3["Sigkill"]
        A4["Sigkill"]
    end

    D1 --> P1 --> A1
    D2 --> P2 --> A2
    D3 --> P3 --> A3
    D4 --> P4 --> A4
```

## MITRE ATT&CK Mapping

All generated policies are tagged with MITRE ATT&CK techniques for compliance and reporting:

| CDR Category | MITRE Technique | Enforcement Action |
|--------------|-----------------|-------------------|
| Cloud_Credentials_Accessed_By_Network_Utility | T1552.005 | Block IMDS access |
| Network_Scanning_Utility | T1046 | Block scanning tools |
| Container_Escape | T1611 | Block namespace manipulation |
| Privilege_Escalation | T1548 | Block setuid(0) |
| Crypto_Mining | T1496 | Block mining pool connections |
| Reverse_Shell | T1059.004 | Block shell spawning |

## Deployment Options

### Option 1: Kubernetes CronJob (Recommended)

Run the operator as a scheduled job that periodically syncs policies:

```mermaid
flowchart LR
    subgraph Schedule["Every Hour"]
        CronJob["CronJob"]
    end

    subgraph Job["Job Execution"]
        Auth["Authenticate"]
        Fetch["Fetch CDR Events"]
        Gen["Generate Policies"]
        Apply["Apply to Cluster"]
    end

    CronJob --> Auth --> Fetch --> Gen --> Apply
```

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: qualys-policy-generator
spec:
  schedule: "0 * * * *"  # Every hour
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: generator
            image: qualys/policy-operator:latest
            args: ["--once", "--hours=24", "--apply"]
            env:
            - name: QUALYS_USERNAME
              valueFrom:
                secretKeyRef:
                  name: qualys-credentials
                  key: username
```

### Option 2: Continuous Controller

Run as a long-running deployment that continuously monitors for new threats:

```mermaid
flowchart TB
    subgraph Controller["Policy Controller"]
        Loop["Main Loop"]
        Timer["1 Hour Timer"]
    end

    subgraph Actions["Actions"]
        Fetch["Fetch Events"]
        Diff["Compare with Existing"]
        Update["Update Policies"]
    end

    Loop --> Timer --> Fetch --> Diff --> Update --> Loop
```

## Policy Lifecycle

Generated policies follow a safe deployment pattern:

```mermaid
stateDiagram-v2
    [*] --> Detected: CDR Event
    Detected --> Generated: Pattern Match
    Generated --> Audit: Deploy with action=Post
    Audit --> Review: Monitor for false positives
    Review --> Enforcement: Approve
    Review --> Tuned: Adjust selectors
    Tuned --> Audit
    Enforcement --> Active: action=Sigkill
    Active --> [*]
```

### Audit Mode First

Always deploy new policies in audit mode first:

```yaml
matchActions:
  - action: Post  # Audit mode - log only
```

After validating no false positives occur, switch to enforcement:

```yaml
matchActions:
  - action: Sigkill  # Kill the process
```

## Example: Cloud Credential Theft Prevention

When CDR detects `curl` accessing the cloud metadata endpoint:

```mermaid
sequenceDiagram
    participant curl
    participant Kernel
    participant Qualys CRS
    participant CDR

    Note over curl: curl 169.254.169.254/...
    curl->>Kernel: sys_connect(169.254.169.254)
    Kernel->>Qualys CRS: kprobe triggered
    Qualys CRS->>Qualys CRS: Match: SAddr=169.254.169.254
    Qualys CRS->>Qualys CRS: Match: Binary=/usr/bin/curl
    Qualys CRS->>curl: SIGKILL
    Qualys CRS->>CDR: Event logged
```

Generated TracingPolicy:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cdr-block-cloud-creds
  labels:
    mitre.attack/technique: T1552.005
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

## Security Considerations

### Credentials Management

Never store credentials in code or ConfigMaps:

```mermaid
flowchart LR
    subgraph Bad["Don't Do This"]
        CM["ConfigMap<br/>with password"]
    end

    subgraph Good["Do This"]
        Secret["Kubernetes Secret"]
        ESO["External Secrets<br/>Operator"]
        Vault["HashiCorp Vault"]
    end

    Secret --> Pod
    ESO --> Secret
    Vault --> ESO
```

### RBAC Restrictions

The operator only needs permission to manage TracingPolicies:

```yaml
rules:
  - apiGroups: ["cilium.io"]
    resources: ["tracingpolicies"]
    verbs: ["get", "list", "create", "update", "patch"]
```

## Metrics and Observability

Track the effectiveness of your automated response:

```mermaid
flowchart TB
    subgraph Metrics["Key Metrics"]
        MTTD["Mean Time to Detect<br/>(CDR)"]
        MTTP["Mean Time to Policy<br/>(Operator)"]
        MTTR["Mean Time to Response<br/>(Total)"]
        Blocked["Attacks Blocked<br/>(Qualys CRS)"]
    end

    subgraph Formula["Calculation"]
        F1["MTTR = MTTD + MTTP"]
    end

    MTTD --> F1
    MTTP --> F1
    F1 --> MTTR
```

With automated policy generation:
- **MTTD**: Minutes (Qualys CDR)
- **MTTP**: 1 hour (CronJob interval)
- **MTTR**: ~1 hour total

Compare to manual response:
- **MTTR**: Hours to days

## Real-Time Blocking with Webhooks

For sub-second response times, deploy the webhook server to receive CDR events in real-time:

```mermaid
sequenceDiagram
    participant Attacker
    participant Container
    participant Qualys CDR
    participant Webhook Server
    participant Qualys CRS

    Attacker->>Container: Malicious activity
    Container->>Qualys CDR: Detection (ms)
    Qualys CDR->>Webhook Server: POST /webhook/cdr
    Webhook Server->>Webhook Server: Extract IOCs
    Webhook Server->>Webhook Server: Check reputation
    Webhook Server->>Qualys CRS: kubectl apply
    Note over Qualys CRS: Policy active
    Attacker->>Container: Repeat attempt
    Qualys CRS->>Attacker: SIGKILL
```

### Webhook Server Architecture

```mermaid
flowchart TB
    subgraph External["External Sources"]
        CDR["Qualys CDR<br/>Webhook"]
        API["Manual API<br/>POST /api/block"]
    end

    subgraph Server["Webhook Server :8080"]
        Auth["HMAC Signature<br/>Verification"]
        Extract["IOC Extraction<br/>- IPs<br/>- Ports<br/>- Domains"]
        Rep["Reputation Check<br/>- AbuseIPDB<br/>- Threat Feeds"]
        Gen["Policy Generator"]
    end

    subgraph Output["Output"]
        File["Policy Files<br/>/policies/*.yaml"]
        Kubectl["kubectl apply"]
        Metrics["Prometheus<br/>/metrics"]
    end

    CDR --> Auth --> Extract --> Rep --> Gen
    API --> Extract
    Gen --> File
    Gen --> Kubectl
    Server --> Metrics
```

### Webhook Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook/cdr` | POST | Receive Qualys CDR events |
| `/api/block` | POST | Manual IP/port blocking |
| `/api/unblock` | POST | Remove blocks |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/status` | GET | Current block status |

### Manual Blocking API

```bash
# Block specific IPs
curl -X POST http://webhook:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ip",
    "values": ["1.2.3.4", "5.6.7.8"],
    "reason": "C2 communication detected",
    "action": "Sigkill"
  }'

# Block suspicious ports
curl -X POST http://webhook:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{
    "type": "port",
    "values": ["4444", "6666"],
    "reason": "Reverse shell ports"
  }'

# Check status
curl http://webhook:8080/status
```

### Configuring Qualys Webhook

In Qualys Console:
1. Go to **TotalCloud > Settings > Integrations**
2. Add new **Webhook** integration
3. Set URL: `https://qualys-webhook.example.com/webhook/cdr`
4. Set secret for HMAC signature verification
5. Select event types: Container threats, CDR detections

### Response Time Comparison

```mermaid
gantt
    title Response Time: Polling vs Webhook
    dateFormat X
    axisFormat %s

    section Polling (1hr)
    Detection       :0, 1
    Wait for poll   :1, 3600
    Generate policy :3600, 3610
    Apply           :3610, 3615

    section Webhook
    Detection       :0, 1
    Webhook POST    :1, 2
    Generate policy :2, 3
    Apply           :3, 4
```

| Metric | Polling (1hr) | Webhook |
|--------|---------------|---------|
| Detection to policy | ~60 min | ~3 sec |
| Attack window | Large | Minimal |
| Resource usage | Lower | Higher |
| Reliability | Higher | Depends on uptime |

## Conclusion

Automated threat response transforms container security from reactive to proactive. By connecting Qualys CDR detection to Qualys CRS enforcement through an automated operator, organizations can:

1. **Reduce response time** from hours/days to minutes
2. **Ensure consistency** in policy generation
3. **Scale security** across large container deployments
4. **Maintain compliance** with MITRE ATT&CK tagging

The feedback loop between detection and enforcement creates a self-improving security posture where each detected threat strengthens overall defenses.

## Next Steps

1. Deploy the operator in your cluster
2. Start with audit mode (`--action=Post`)
3. Monitor for false positives
4. Gradually enable enforcement
5. Integrate with your SIEM for alerting

---

*For implementation details, see the [operator documentation](../operator/README.md).*
