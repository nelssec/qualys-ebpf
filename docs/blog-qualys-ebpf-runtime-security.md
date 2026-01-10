# Qualys CRS: Enterprise Kubernetes Runtime Security

## Introduction

Kubernetes has become the de facto standard for container orchestration, but securing containerized workloads at runtime remains one of the most challenging aspects of cloud-native security. Traditional security tools struggle with the ephemeral nature of containers, the complexity of microservices communication, and the need for real-time threat detection without impacting performance.

**Qualys Container Runtime Security (CRS)** addresses these challenges by combining the power of eBPF (Extended Berkeley Packet Filter) with enterprise-grade security features, providing deep visibility into container behavior while enabling real-time threat prevention.

## What is Qualys CRS?

Qualys CRS is an open-source Kubernetes runtime security solution using eBPF-based enforcement via Qualys TracingPolicies and network security via Qualys NetworkPolicies. It provides:

- **49 detection rules** mapped to MITRE ATT&CK techniques
- **AI-powered anomaly detection** for behavioral analysis
- **Multi-cluster federation** for enterprise-scale deployments
- **Real-time response actions** including process termination, container isolation, and forensic capture

## Key Capabilities

### 1. Comprehensive Detection Coverage

The solution includes 49 detection rules covering the full MITRE ATT&CK framework for containers:

| Attack Category | Rules | Example Detections |
|----------------|-------|-------------------|
| Persistence | 8 | Cron job creation, systemd service installation, kernel module loading |
| Privilege Escalation | 10 | Setuid abuse, capability manipulation, sudo exploitation |
| Credential Access | 6 | /etc/shadow access, SSH key theft, cloud credential access |
| Defense Evasion | 7 | Log tampering, timestomping, process masquerading |
| Lateral Movement | 4 | SSH pivoting, kubectl exec abuse, network scanning |
| Execution | 5 | Reverse shells, script interpreter abuse, container exec |
| Command & Control | 3 | DNS tunneling, encrypted channels, unusual ports |
| Exfiltration | 3 | Data staging, cloud storage upload, encoding |

Each rule is tagged with MITRE ATT&CK techniques and tactics, enabling security teams to understand the threat context and prioritize response.

### 2. AI-Powered Anomaly Detection

Traditional signature-based detection misses zero-day attacks and novel techniques. Qualys CRS includes multiple AI/ML algorithms for behavioral anomaly detection:

**Statistical Analysis:**
- Z-score detection for sudden metric spikes
- Interquartile Range (IQR) analysis for robust outlier detection
- Time series analysis for trend changes and baseline drift

**Machine Learning:**
- **Isolation Forest**: Unsupervised algorithm that isolates anomalies by randomly partitioning data. Effective for high-dimensional data without requiring labeled training sets.
- **K-Means Clustering**: Groups containers by behavioral similarity, flagging those far from cluster centroids as potential threats.

**Learning Period:**
The system observes container behavior for a configurable period (default 48 hours) before enabling anomaly detection. This prevents false positives from legitimate but unusual application behavior during initial deployment.

```yaml
# Example: AI detector configuration
aiDetector:
  learningPeriod: 48h
  zScoreThreshold: 3.0
  isolationForest:
    numTrees: 100
    sampleSize: 256
    anomalyThreshold: 0.6
  retrainingInterval: 6h
```

### 3. Multi-Cluster Federation

Enterprise environments often span multiple Kubernetes clusters across regions, cloud providers, and environments. Qualys CRS provides native multi-cluster support through a hub-spoke federation model:

**Hub Cluster:**
- Central policy management and distribution
- Event aggregation from all spoke clusters
- Cross-cluster attack correlation
- Unified dashboard and reporting

**Spoke Clusters:**
- Receive and apply federated policies
- Forward events to hub for correlation
- Local enforcement with hub oversight
- Heartbeat monitoring for health tracking

**Federation CRDs:**

```yaml
# Register a spoke cluster
apiVersion: federation.qualys.com/v1alpha1
kind: FederatedCluster
metadata:
  name: prod-us-east
  labels:
    environment: production
    region: us-east
spec:
  endpoint: https://prod-us-east.k8s.example.com:6443
  provider: aws
  secretRef:
    name: spoke-credentials
    namespace: qualys-system
```

```yaml
# Distribute policy to all production clusters
apiVersion: federation.qualys.com/v1alpha1
kind: FederatedTracingPolicy
metadata:
  name: block-cryptominers-global
spec:
  template:
    spec:
      kprobes:
        - call: sys_execve
          syscall: true
          selectors:
            - matchArgs:
                - index: 0
                  operator: In
                  values: [xmrig, minerd, cpuminer]
              matchActions:
                - action: Sigkill
  placement:
    clusterSelector:
      matchLabels:
        environment: production
```

**Cross-Cluster Attack Detection:**

The federation manager correlates events across clusters to detect:
- **Coordinated Attacks**: Same attack pattern appearing in multiple clusters simultaneously
- **Lateral Movement**: Reconnaissance in one cluster followed by exploitation in another
- **Supply Chain Indicators**: Cryptominer or malware in multiple clusters suggesting compromised base images

### 4. Real-Time Response Actions

Detection is only valuable if you can respond quickly. Qualys CRS provides multiple response options:

| Action | Description | Use Case |
|--------|-------------|----------|
| Process Kill | SIGKILL to malicious process | Immediate threat termination |
| Container Stop | Graceful container shutdown | Suspicious but uncertain threat |
| Container Pause | Freeze all processes | Forensic preservation |
| File Quarantine | Compress and isolate file | Malware isolation |
| Forensics Capture | Collect process info, logs, files | Incident response |
| Network Isolate | Apply deny-all NetworkPolicy | Contain lateral movement |

Actions can be triggered automatically based on detection confidence or manually through the API.

### 5. Kubernetes Admission Controller

Shift-left security by validating pods before they're deployed:

```yaml
# Default admission policy
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
requireResourceLimits: false
```

The admission controller integrates with the detection engine, allowing you to block pods that match known-bad patterns before they even start.

### 6. DNS Threat Monitoring

DNS is often overlooked but is a common vector for C2 communication and data exfiltration:

- **Threat Intelligence**: Block queries to known malicious domains (C2, phishing, mining pools)
- **DGA Detection**: Entropy-based detection of algorithmically generated domains
- **Query Tracking**: Monitor and analyze DNS patterns for anomalies
- **Policy Generation**: Automatically generate Qualys NetworkPolicy for DNS blocking

### 7. SIEM/SOAR Integration

Security events need to reach your existing tools:

| Integration | Format | Features |
|-------------|--------|----------|
| Slack | Rich messages | Color-coded severity, quick actions |
| PagerDuty | Incidents | Auto-escalation for critical alerts |
| Microsoft Teams | MessageCards | Full event context |
| Splunk HEC | JSON | Native indexing, correlation |
| Elasticsearch | Documents | Full-text search, dashboards |
| Syslog | CEF | SIEM compatibility |

## Architecture Deep Dive

### eBPF Enforcement Layer

The solution uses Qualys TracingPolicies for syscall-level enforcement:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-container-escape
spec:
  kprobes:
    - call: sys_setns
      syscall: true
      args:
        - index: 1
          type: int
      selectors:
        - matchNamespaces:
            - namespace: Mnt
              operator: NotIn
              values: ["host_mnt"]
          matchActions:
            - action: Sigkill
```

Key advantages of eBPF:
- **Zero-overhead**: Runs in kernel space, no container instrumentation
- **Tamper-proof**: Cannot be disabled by container processes
- **Real-time**: Intercepts syscalls before they execute
- **Persistent**: LSM hooks remain active even if agent crashes

### Network Security Layer

Qualys NetworkPolicies provide L3/L4/L7 network enforcement:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: block-crypto-pools
spec:
  endpointSelector: {}
  egressDeny:
    - toFQDNs:
        - matchPattern: "*.minexmr.com"
        - matchPattern: "*.minergate.com"
      toPorts:
        - ports:
            - port: "443"
            - port: "3333"
```

## Getting Started

### Quick Install

```bash
# Add Helm repo
helm repo add qualys-ebpf https://qualys.github.io/qualys-ebpf/

# Install with default configuration
helm install qualys-crs qualys-ebpf/qualys-crs \
  --namespace qualys-system \
  --create-namespace \
  --set qualys.username=$QUALYS_USERNAME \
  --set qualys.password=$QUALYS_PASSWORD
```

### Deploy Detection Policies

```bash
# Development (audit only)
kubectl apply -k policies/crs-detections/kustomize/overlays/dev

# Production (full enforcement)
kubectl apply -k policies/crs-detections/kustomize/overlays/prod
```

### Enable Federation

```bash
# On hub cluster
kubectl apply -f operator/config/crds/

# Register spoke clusters
kubectl apply -f operator/config/samples/federation-example.yaml
```

## Performance

The solution is designed for production workloads with minimal overhead:

| Operation | Latency | Memory |
|-----------|---------|--------|
| AI Anomaly Detection | 27μs | 17KB |
| Isolation Forest Scoring | 5.7μs | 0B |
| Input Validation | <400ns | 0B |
| Cross-Cluster Correlation | 2.3μs | 2.5KB |

All critical packages include comprehensive unit tests (71 tests total) with 46-75% code coverage.

## Conclusion

Kubernetes runtime security requires a comprehensive approach that combines:
- Deep visibility through eBPF
- Intelligent detection through AI/ML
- Rapid response through automated actions
- Enterprise scale through multi-cluster federation

Qualys CRS provides all of these capabilities in an open-source solution that integrates with your existing security stack and Qualys platform.

## Resources

- [GitHub Repository](https://github.com/qualys/qualys-ebpf)
- [Qualys TracingPolicy Reference](../policies/library/)
- [Qualys NetworkPolicy Reference](../policies/network/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Qualys Container Security](https://www.qualys.com/apps/container-security/)
