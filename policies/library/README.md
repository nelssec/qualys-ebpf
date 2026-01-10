# Qualys Policy Library

This directory contains curated security policies aligned with industry best practices from:
- [Falco Rules](https://github.com/falcosecurity/rules)
- [Qualys TracingPolicy Reference](../crs-detections/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## Maturity Levels

Following Falco's maturity framework:

| Level | Description |
|-------|-------------|
| **stable** | Production-ready, well-tested, low false positive rate |
| **incubating** | Robust but may need tuning for specific environments |
| **sandbox** | Experimental, may have higher false positive rates |

## Priority Levels

| Priority | Use Case |
|----------|----------|
| **CRITICAL** | Immediate threat requiring instant response (Sigkill) |
| **HIGH** | Significant threat, alert immediately |
| **MEDIUM** | Suspicious activity, investigate |
| **LOW** | Informational, baseline deviation |

## MITRE ATT&CK Mapping

All policies include MITRE ATT&CK technique tags:
- `mitre.attack/tactic` - The attack tactic (e.g., `execution`, `privilege-escalation`)
- `mitre.attack/technique` - The technique ID (e.g., `T1059.004`)

## Policy Categories

| Category | Description |
|----------|-------------|
| `process` | Process execution monitoring |
| `file` | File access and modification |
| `network` | Network connections and traffic |
| `container` | Container-specific behaviors |
| `syscall` | Low-level syscall monitoring |
| `credentials` | Credential access and theft |
