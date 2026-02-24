#!/usr/bin/env python3
"""Qualys Container Runtime Security (CRS) Event Catalog.

Security event definitions aligned with Qualys CDR threat categories:
- MITRE ATT&CK mapping
- Detection signatures (syscalls, files, processes)
- TracingPolicy templates for Tetragon/Cilium eBPF enforcement
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import yaml


@dataclass
class SecurityEvent:
    """Security event definition with detection signatures."""
    id: str
    name: str
    description: str
    qualys_category: str
    mitre_techniques: List[str]
    severity: str
    syscalls: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)
    process_patterns: List[str] = field(default_factory=list)
    network_patterns: Dict[str, Any] = field(default_factory=dict)
    args_patterns: List[str] = field(default_factory=list)
    detection_logic: str = ""
    false_positive_notes: str = ""


SECURITY_EVENTS: Dict[str, SecurityEvent] = {
    "container_escape_namespace": SecurityEvent(
        id="QCR001",
        name="Container Namespace Breakout Attempt",
        description="Mount or namespace manipulation indicating container escape attempt",
        qualys_category="Container_Escape",
        mitre_techniques=["T1611"],
        severity="CRITICAL",
        syscalls=["sys_mount", "sys_unshare", "sys_setns"],
        file_patterns=["/proc/1/ns/", "/proc/self/ns/"],
        args_patterns=["MNT", "CLONE_NEWNS"],
        detection_logic="Track namespace and mount syscalls for escape attempts",
    ),

    "container_escape_cgroup": SecurityEvent(
        id="QCR002",
        name="Cgroup Release Agent Exploitation",
        description="Container escape via cgroup release_agent mechanism",
        qualys_category="Container_Escape",
        mitre_techniques=["T1611"],
        severity="CRITICAL",
        syscalls=["sys_openat", "sys_write"],
        file_patterns=[
            "/sys/fs/cgroup/*/release_agent",
            "/sys/fs/cgroup/*/notify_on_release"
        ],
        detection_logic="Monitor cgroup release_agent file modifications",
    ),

    "privilege_escalation_suid": SecurityEvent(
        id="QCR003",
        name="SUID/SGID Binary Reconnaissance",
        description="Scanning for setuid binaries as privilege escalation vectors",
        qualys_category="Privilege_Escalation",
        mitre_techniques=["T1548.001", "T1083"],
        severity="MEDIUM",
        syscalls=["sys_execve"],
        process_patterns=["find"],
        args_patterns=["-perm", "+4000", "-4000", "+2000", "-u=s", "-g=s"],
        detection_logic="Detect find commands searching for SUID/SGID bits",
    ),

    "privilege_escalation_setuid": SecurityEvent(
        id="QCR004",
        name="Setuid Permission Applied",
        description="SUID or SGID bit set on binary file",
        qualys_category="Privilege_Escalation",
        mitre_techniques=["T1548.001"],
        severity="CRITICAL",
        syscalls=["sys_chmod", "sys_fchmod", "sys_fchmodat"],
        args_patterns=["4755", "2755", "6755", "u+s", "g+s"],
        detection_logic="Track chmod calls with SUID/SGID bits",
    ),

    "privilege_escalation_capability": SecurityEvent(
        id="QCR005",
        name="Linux Capability Escalation",
        description="Elevated capabilities granted to binary or process",
        qualys_category="Privilege_Escalation",
        mitre_techniques=["T1548.001", "T1068"],
        severity="HIGH",
        syscalls=["sys_capset"],
        process_patterns=["setcap", "getcap"],
        args_patterns=["cap_setuid", "cap_setgid", "cap_sys_admin", "cap_net_admin"],
        detection_logic="Track dangerous capability assignments",
    ),

    "credential_cloud_metadata_aws": SecurityEvent(
        id="QCR006",
        name="AWS IMDS Credential Access",
        description="Container accessing AWS EC2 instance metadata service",
        qualys_category="Cloud_Credentials_Accessed_By_Network_Utility",
        mitre_techniques=["T1552.005", "T1078.004"],
        severity="CRITICAL",
        syscalls=["sys_connect"],
        network_patterns={
            "addresses": ["169.254.169.254", "fd00:ec2::254"],
            "ports": [80, 443],
        },
        process_patterns=["curl", "wget", "python", "ruby", "node"],
        detection_logic="Track requests to AWS metadata service endpoints",
    ),

    "credential_cloud_metadata_gcp": SecurityEvent(
        id="QCR007",
        name="GCP Metadata Service Credential Access",
        description="Container accessing Google Cloud metadata endpoints",
        qualys_category="Cloud_Credentials_Accessed_By_Network_Utility",
        mitre_techniques=["T1552.005"],
        severity="CRITICAL",
        syscalls=["sys_connect"],
        network_patterns={
            "addresses": ["169.254.169.254", "metadata.google.internal"],
            "ports": [80],
        },
        detection_logic="Track GCP metadata endpoint requests",
    ),

    "credential_cloud_metadata_azure": SecurityEvent(
        id="QCR008",
        name="Azure IMDS Credential Access",
        description="Container accessing Azure Instance Metadata Service",
        qualys_category="Cloud_Credentials_Accessed_By_Network_Utility",
        mitre_techniques=["T1552.005"],
        severity="CRITICAL",
        syscalls=["sys_connect"],
        network_patterns={
            "addresses": ["169.254.169.254"],
            "ports": [80],
        },
        detection_logic="Track Azure IMDS endpoint requests",
    ),

    "credential_file_access": SecurityEvent(
        id="QCR009",
        name="Sensitive Credential File Access",
        description="Access to system credential and authentication files",
        qualys_category="Credential_Access",
        mitre_techniques=["T1552.001", "T1003.008"],
        severity="HIGH",
        syscalls=["sys_openat", "sys_read"],
        file_patterns=[
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/root/.ssh/", "/home/*/.ssh/"
        ],
        detection_logic="Monitor reads of credential and authentication files",
    ),

    "credential_cloud_file_azure": SecurityEvent(
        id="QCR010",
        name="Azure Cloud Credential File Access",
        description="Access to Azure authentication tokens and configuration",
        qualys_category="Credential_Access",
        mitre_techniques=["T1552.001", "T1552.004"],
        severity="HIGH",
        syscalls=["sys_openat", "sys_read"],
        file_patterns=[
            "/.azure/", "/azure.json", "/.azure/accessTokens.json",
            "/.azure/azureProfile.json"
        ],
        detection_logic="Track access to Azure credential storage locations",
    ),

    "credential_cloud_file_aws": SecurityEvent(
        id="QCR011",
        name="AWS Credential File Access",
        description="Access to AWS credentials and configuration files",
        qualys_category="Credential_Access",
        mitre_techniques=["T1552.001"],
        severity="HIGH",
        syscalls=["sys_openat", "sys_read"],
        file_patterns=["/.aws/credentials", "/.aws/config"],
        detection_logic="Track access to AWS credential files",
    ),

    "credential_k8s_secret": SecurityEvent(
        id="QCR012",
        name="Kubernetes Service Account Token Access",
        description="Access to Kubernetes service account credentials",
        qualys_category="Credential_Access",
        mitre_techniques=["T1552.007"],
        severity="MEDIUM",
        syscalls=["sys_openat", "sys_read"],
        file_patterns=["/var/run/secrets/kubernetes.io/serviceaccount/token"],
        detection_logic="Track K8s service account token reads",
    ),

    "credential_private_key_search": SecurityEvent(
        id="QCR013",
        name="Private Key and Secret Discovery",
        description="File system searches targeting cryptographic keys",
        qualys_category="Credential_Access",
        mitre_techniques=["T1552.001", "T1552.004"],
        severity="HIGH",
        syscalls=["sys_execve", "sys_openat"],
        process_patterns=["find", "grep", "locate"],
        args_patterns=[
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            ".pem", ".key", ".p12", ".pfx"
        ],
        file_patterns=["/.ssh/", "/.gnupg/", "/.kube/"],
        detection_logic="Identify searches for key and credential patterns",
    ),

    "crypto_mining_stratum": SecurityEvent(
        id="QCR014",
        name="Cryptocurrency Mining Protocol",
        description="Network activity consistent with Stratum mining pool communication",
        qualys_category="Crypto_Mining",
        mitre_techniques=["T1496"],
        severity="HIGH",
        syscalls=["sys_connect", "sys_sendto"],
        network_patterns={
            "ports": [3333, 4444, 5555, 8333, 9999, 14433, 14444],
        },
        process_patterns=["xmrig", "minerd", "cpuminer", "ethminer", "cgminer", "bfgminer"],
        detection_logic="Detect connections to known mining pool ports",
    ),

    "crypto_mining_binary": SecurityEvent(
        id="QCR015",
        name="Cryptocurrency Miner Execution",
        description="Known cryptomining binary executed in container",
        qualys_category="Crypto_Mining",
        mitre_techniques=["T1496"],
        severity="HIGH",
        syscalls=["sys_execve"],
        process_patterns=[
            "xmrig", "xmr-stak", "minerd", "cpuminer", "cgminer",
            "bfgminer", "ethminer", "ccminer", "nheqminer"
        ],
        detection_logic="Track cryptominer binary execution",
    ),

    "network_scanning_tool": SecurityEvent(
        id="QCR016",
        name="Network Scanning Utility Execution",
        description="Network reconnaissance tool executed in container",
        qualys_category="Network_Scanning_Utility",
        mitre_techniques=["T1046", "T1595"],
        severity="HIGH",
        syscalls=["sys_execve", "sys_socket"],
        process_patterns=[
            "nmap", "masscan", "zmap", "rustscan",
            "netdiscover", "arp-scan", "fping"
        ],
        detection_logic="Track network scanning tool execution",
    ),

    "network_scanning_raw_socket": SecurityEvent(
        id="QCR017",
        name="Raw Socket Network Scan",
        description="Raw socket creation for network scanning",
        qualys_category="Network_Scanning_Utility",
        mitre_techniques=["T1046"],
        severity="MEDIUM",
        syscalls=["sys_socket"],
        args_patterns=["SOCK_RAW", "3"],
        detection_logic="Monitor raw socket creation",
    ),

    "c2_reverse_shell_bash": SecurityEvent(
        id="QCR018",
        name="Reverse Shell - Bash TCP",
        description="Bash process with outbound socket for remote control",
        qualys_category="Networking_C2_Communication",
        mitre_techniques=["T1059.004", "T1071.001"],
        severity="CRITICAL",
        syscalls=["sys_execve", "sys_connect", "sys_dup2"],
        process_patterns=["sh", "bash", "dash"],
        args_patterns=["/dev/tcp/", "/dev/udp/", "0>&1", ">&/dev/tcp"],
        detection_logic="Identify bash reverse shell patterns",
    ),

    "c2_reverse_shell_python": SecurityEvent(
        id="QCR019",
        name="Reverse Shell - Python Socket",
        description="Python process with socket-based command channel",
        qualys_category="Networking_C2_Communication",
        mitre_techniques=["T1059.006", "T1071.001"],
        severity="CRITICAL",
        syscalls=["sys_execve", "sys_connect", "sys_dup2"],
        process_patterns=["python", "python3", "python2"],
        args_patterns=["socket", "subprocess", "pty.spawn", "os.dup2", "SOCK_STREAM"],
        detection_logic="Track Python socket connections with shell spawn",
    ),

    "c2_reverse_shell_netcat": SecurityEvent(
        id="QCR020",
        name="Reverse Shell - Netcat",
        description="Netcat or similar tool with shell execution capabilities",
        qualys_category="Networking_C2_Communication",
        mitre_techniques=["T1059", "T1071.001"],
        severity="CRITICAL",
        syscalls=["sys_execve", "sys_connect", "sys_dup2"],
        process_patterns=["nc", "ncat", "netcat", "nc.traditional", "nc.openbsd"],
        args_patterns=["-e", "-c", "/bin/sh", "/bin/bash"],
        detection_logic="Identify netcat with command execution flags",
    ),

    "c2_tunnel_tool": SecurityEvent(
        id="QCR021",
        name="Network Tunnel for C2",
        description="Tunneling tool used for potential C2 or exfiltration",
        qualys_category="Networking_C2_Communication",
        mitre_techniques=["T1572", "T1048"],
        severity="HIGH",
        syscalls=["sys_execve", "sys_connect"],
        process_patterns=["socat", "stunnel", "sshuttle", "chisel", "ligolo", "ngrok"],
        detection_logic="Detect tunnel/relay tool invocation",
    ),

    "c2_suspicious_port": SecurityEvent(
        id="QCR022",
        name="Suspicious Outbound Connection",
        description="Connection to known C2 or suspicious ports",
        qualys_category="Networking_Suspicious_Communication",
        mitre_techniques=["T1071"],
        severity="HIGH",
        syscalls=["sys_connect"],
        network_patterns={
            "ports": [4444, 5555, 6666, 8443, 1337, 31337],
        },
        detection_logic="Monitor connections to suspicious ports",
    ),

    "defense_evasion_security_tool_kill": SecurityEvent(
        id="QCR023",
        name="Security Agent Termination",
        description="Attempts to terminate security monitoring processes",
        qualys_category="Defense_Evasion",
        mitre_techniques=["T1562.001"],
        severity="HIGH",
        syscalls=["sys_kill", "sys_tkill", "sys_tgkill"],
        process_patterns=[
            "falcon-sensor", "cbagent", "qualys-cloud-agent", "tetragon", "falco",
            "osquery", "auditd", "cilium-agent"
        ],
        detection_logic="Monitor termination signals to security processes",
    ),

    "defense_evasion_security_config": SecurityEvent(
        id="QCR024",
        name="Security Tool Configuration Tampering",
        description="Modification of security software configuration",
        qualys_category="Defense_Evasion",
        mitre_techniques=["T1562.001", "T1562.004"],
        severity="CRITICAL",
        syscalls=["sys_openat", "sys_write", "sys_unlink"],
        file_patterns=[
            "/etc/falco/", "/etc/tetragon/", "/etc/qualys/",
            "/opt/qualys/", "/var/spool/qualys/"
        ],
        detection_logic="Track modifications to security tool configurations",
    ),

    "defense_evasion_log_tampering": SecurityEvent(
        id="QCR025",
        name="Log File Evasion",
        description="Log redirection or deletion for audit evasion",
        qualys_category="Defense_Evasion",
        mitre_techniques=["T1070.002", "T1036"],
        severity="HIGH",
        syscalls=["sys_symlink", "sys_symlinkat", "sys_unlink"],
        file_patterns=["/var/log/", "/dev/null"],
        detection_logic="Track log file redirection or deletion",
    ),

    "defense_evasion_mac_disable": SecurityEvent(
        id="QCR026",
        name="Mandatory Access Control Disabled",
        description="AppArmor or SELinux security controls weakened",
        qualys_category="Defense_Evasion",
        mitre_techniques=["T1562.001"],
        severity="CRITICAL",
        syscalls=["sys_write", "sys_openat"],
        file_patterns=[
            "/sys/kernel/security/apparmor/",
            "/etc/selinux/config",
            "/sys/fs/selinux/enforce"
        ],
        process_patterns=["setenforce", "aa-disable"],
        detection_logic="Track MAC policy changes",
    ),

    "persistence_cron": SecurityEvent(
        id="QCR027",
        name="Cron Job Persistence",
        description="Creation or modification of scheduled tasks",
        qualys_category="Persistence",
        mitre_techniques=["T1053.003"],
        severity="HIGH",
        syscalls=["sys_openat", "sys_write"],
        file_patterns=[
            "/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/",
            "/var/spool/cron/", "/var/spool/cron/crontabs/"
        ],
        detection_logic="Track cron configuration changes",
    ),

    "persistence_systemd": SecurityEvent(
        id="QCR028",
        name="Systemd Service Persistence",
        description="Installation of systemd service for persistence",
        qualys_category="Persistence",
        mitre_techniques=["T1543.002"],
        severity="HIGH",
        syscalls=["sys_openat", "sys_write"],
        file_patterns=[
            "/etc/systemd/system/",
            "/usr/lib/systemd/system/",
            "/lib/systemd/system/"
        ],
        detection_logic="Track systemd service installation",
    ),

    "persistence_ssh_key": SecurityEvent(
        id="QCR029",
        name="SSH Authorized Key Injection",
        description="Modification of SSH authorized_keys for backdoor access",
        qualys_category="Persistence",
        mitre_techniques=["T1098.004", "T1556"],
        severity="HIGH",
        syscalls=["sys_openat", "sys_write"],
        file_patterns=[
            "/root/.ssh/authorized_keys",
            "/home/*/.ssh/authorized_keys"
        ],
        detection_logic="Track authorized_keys file modifications",
    ),

    "persistence_ld_preload": SecurityEvent(
        id="QCR030",
        name="Dynamic Linker Hijacking",
        description="Tampering with ld.so.preload for library injection",
        qualys_category="Persistence",
        mitre_techniques=["T1574.006", "T1055"],
        severity="CRITICAL",
        syscalls=["sys_openat", "sys_write"],
        file_patterns=["/etc/ld.so.preload", "/etc/ld.so.conf"],
        detection_logic="Monitor modifications to dynamic linker configuration",
    ),

    "persistence_kernel_module": SecurityEvent(
        id="QCR031",
        name="Kernel Module Installation",
        description="Loading kernel module potentially for rootkit",
        qualys_category="Persistence",
        mitre_techniques=["T1547.006", "T1014"],
        severity="CRITICAL",
        syscalls=["sys_init_module", "sys_finit_module"],
        process_patterns=["insmod", "modprobe"],
        detection_logic="Track kernel module loading operations",
    ),

    "execution_shell_obfuscated": SecurityEvent(
        id="QCR032",
        name="Encoded Shell Command Execution",
        description="Shell interpreter executing base64-encoded commands",
        qualys_category="Execution",
        mitre_techniques=["T1059.004", "T1027"],
        severity="HIGH",
        syscalls=["sys_execve"],
        process_patterns=["sh", "bash", "dash", "zsh"],
        args_patterns=["base64", "-d", "| sh", "| bash", "eval", "$(echo"],
        detection_logic="Identify shell commands with base64 decoding",
    ),

    "execution_python_obfuscated": SecurityEvent(
        id="QCR033",
        name="Encoded Python Payload Execution",
        description="Python interpreter running base64-obfuscated code",
        qualys_category="Execution",
        mitre_techniques=["T1059.006", "T1027"],
        severity="HIGH",
        syscalls=["sys_execve"],
        process_patterns=["python", "python3", "python2"],
        args_patterns=["-c", "base64", "b64decode", "exec(", "eval("],
        detection_logic="Identify Python with encoding/decoding in arguments",
    ),

    "execution_compiler_runtime": SecurityEvent(
        id="QCR034",
        name="Build Tool in Runtime Container",
        description="Compiler or build tools running in production environment",
        qualys_category="Execution",
        mitre_techniques=["T1027.004", "T1059"],
        severity="MEDIUM",
        syscalls=["sys_execve"],
        process_patterns=["gcc", "g++", "clang", "make", "cc", "as", "ld", "rustc", "go"],
        detection_logic="Track compiler execution in containers",
    ),

    "execution_webshell": SecurityEvent(
        id="QCR035",
        name="Web Server Shell Execution",
        description="Web server process spawning command interpreter",
        qualys_category="Execution",
        mitre_techniques=["T1505.003"],
        severity="CRITICAL",
        syscalls=["sys_execve", "sys_fork", "sys_clone"],
        process_patterns=["sh", "bash", "whoami", "id", "uname"],
        detection_logic="Track shell spawning from web processes",
    ),

    "discovery_k8s_api": SecurityEvent(
        id="QCR036",
        name="Kubernetes API Discovery",
        description="Container process accessing Kubernetes API server",
        qualys_category="Discovery",
        mitre_techniques=["T1613", "T1552.007"],
        severity="MEDIUM",
        syscalls=["sys_connect"],
        network_patterns={
            "addresses": ["kubernetes.default.svc", "10.96.0.1"],
            "ports": [443, 6443],
        },
        detection_logic="Track K8s API communication",
    ),

    "lateral_movement_ssh": SecurityEvent(
        id="QCR037",
        name="SSH Lateral Movement",
        description="Outbound SSH connection to internal network hosts",
        qualys_category="Lateral_Movement",
        mitre_techniques=["T1021.004"],
        severity="HIGH",
        syscalls=["sys_execve", "sys_connect"],
        process_patterns=["ssh", "scp", "sftp"],
        network_patterns={"ports": [22]},
        detection_logic="Track SSH connections from containers",
    ),

    "impact_data_destruction": SecurityEvent(
        id="QCR038",
        name="Bulk Data Removal",
        description="Large-scale file deletion suggesting data destruction",
        qualys_category="Impact",
        mitre_techniques=["T1485", "T1070"],
        severity="CRITICAL",
        syscalls=["sys_unlink", "sys_unlinkat", "sys_rmdir"],
        process_patterns=["rm", "shred", "wipe"],
        args_patterns=["-rf", "-r", "--no-preserve-root"],
        detection_logic="Identify recursive or bulk deletion commands",
    ),

    "collection_memory_dump": SecurityEvent(
        id="QCR039",
        name="Process Memory Credential Harvesting",
        description="Memory access patterns consistent with credential extraction",
        qualys_category="Collection",
        mitre_techniques=["T1003.007", "T1003"],
        severity="CRITICAL",
        syscalls=["sys_ptrace", "sys_process_vm_readv"],
        file_patterns=["/proc/*/mem", "/proc/*/maps", "/dev/mem"],
        process_patterns=["gdb", "strace", "ltrace", "gcore"],
        detection_logic="Track ptrace and memory read operations",
    ),

    "collection_env_secrets": SecurityEvent(
        id="QCR040",
        name="Process Environment Secret Access",
        description="Reading process environment containing secrets",
        qualys_category="Collection",
        mitre_techniques=["T1552.007"],
        severity="HIGH",
        syscalls=["sys_openat", "sys_read"],
        file_patterns=["/proc/*/environ", "/proc/self/environ"],
        detection_logic="Track /proc environ file access",
    ),
}


def get_event_by_id(event_id: str) -> Optional[SecurityEvent]:
    """Get a security event by its ID."""
    for event in SECURITY_EVENTS.values():
        if event.id.upper() == event_id.upper():
            return event
    return None


def get_events_by_category(category: str) -> List[SecurityEvent]:
    """Get all events in a Qualys category."""
    return [e for e in SECURITY_EVENTS.values() if e.qualys_category.lower() == category.lower()]


def get_events_by_mitre(technique: str) -> List[SecurityEvent]:
    """Get all events matching a MITRE technique."""
    return [e for e in SECURITY_EVENTS.values() if technique in e.mitre_techniques]


def generate_tracing_policy(event: SecurityEvent, action: str = "Post") -> Dict[str, Any]:
    """Generate a TracingPolicy for a security event."""
    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": f"qcr-{event.id.lower()}-{event.name.lower().replace(' ', '-')[:25]}",
            "labels": {
                "qualys.com/event-id": event.id,
                "qualys.com/category": event.qualys_category.lower().replace("_", "-"),
                "qualys.com/severity": event.severity.lower(),
                "app.kubernetes.io/managed-by": "qualys-crs",
            },
            "annotations": {
                "qualys.com/description": event.description,
                "qualys.com/mitre-techniques": ",".join(event.mitre_techniques),
                "qualys.com/detection-logic": event.detection_logic,
            },
        },
        "spec": {"kprobes": []},
    }

    for syscall in event.syscalls:
        kprobe = {
            "call": syscall,
            "syscall": True,
            "args": [],
            "selectors": [],
        }

        if syscall in ["sys_openat", "sys_open"]:
            kprobe["args"] = [{"index": 1, "type": "string"}]
            if event.file_patterns:
                kprobe["selectors"].append({
                    "matchArgs": [{
                        "index": 1,
                        "operator": "Prefix",
                        "values": event.file_patterns[:10],
                    }],
                    "matchActions": [{"action": action}],
                })

        elif syscall == "sys_execve":
            kprobe["args"] = [
                {"index": 0, "type": "string"},
                {"index": 1, "type": "string"},
            ]
            if event.process_patterns:
                kprobe["selectors"].append({
                    "matchArgs": [{
                        "index": 0,
                        "operator": "Postfix",
                        "values": [f"/{p}" for p in event.process_patterns[:10]],
                    }],
                    "matchActions": [{"action": action}],
                })

        elif syscall == "sys_connect":
            kprobe["args"] = [{"index": 1, "type": "sockaddr"}]
            if event.network_patterns.get("ports"):
                kprobe["selectors"].append({
                    "matchArgs": [{
                        "index": 1,
                        "operator": "DPort",
                        "values": [str(p) for p in event.network_patterns["ports"][:10]],
                    }],
                    "matchActions": [{"action": action}],
                })
            elif event.network_patterns.get("addresses"):
                kprobe["selectors"].append({
                    "matchArgs": [{
                        "index": 1,
                        "operator": "SAddr",
                        "values": event.network_patterns["addresses"][:10],
                    }],
                    "matchActions": [{"action": action}],
                })

        elif syscall in ["sys_symlink", "sys_symlinkat", "sys_link", "sys_linkat"]:
            kprobe["args"] = [
                {"index": 0, "type": "string"},
                {"index": 1, "type": "string"},
            ]
            kprobe["selectors"].append({
                "matchActions": [{"action": action}],
            })

        elif syscall in ["sys_kill", "sys_tkill", "sys_tgkill"]:
            kprobe["args"] = [
                {"index": 0, "type": "int"},
                {"index": 1, "type": "int"},
            ]
            kprobe["selectors"].append({
                "matchActions": [{"action": action}],
            })

        elif syscall == "sys_ptrace":
            kprobe["args"] = [
                {"index": 0, "type": "int"},
                {"index": 1, "type": "int"},
            ]
            kprobe["selectors"].append({
                "matchActions": [{"action": action}],
            })

        elif syscall in ["sys_init_module", "sys_finit_module"]:
            kprobe["args"] = [{"index": 0, "type": "string"}]
            kprobe["selectors"].append({
                "matchActions": [{"action": action}],
            })

        elif syscall == "sys_socket":
            kprobe["args"] = [
                {"index": 0, "type": "int"},
                {"index": 1, "type": "int"},
            ]
            kprobe["selectors"].append({
                "matchArgs": [{
                    "index": 1,
                    "operator": "Equal",
                    "values": ["3"],
                }],
                "matchActions": [{"action": action}],
            })

        else:
            kprobe["selectors"].append({
                "matchActions": [{"action": action}],
            })

        if kprobe["selectors"]:
            policy["spec"]["kprobes"].append(kprobe)

    return policy


def generate_all_policies(action: str = "Post", output_dir: str = "./event-policies") -> List[str]:
    """Generate TracingPolicies for all security events."""
    import os
    os.makedirs(output_dir, exist_ok=True)

    files = []
    for key, event in SECURITY_EVENTS.items():
        policy = generate_tracing_policy(event, action)
        filename = f"{event.id.lower()}-{key}.yaml"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        files.append(filepath)

    return files


def list_events(category: Optional[str] = None, severity: Optional[str] = None) -> str:
    """Format event list for CLI output."""
    lines = []
    lines.append(f"{'ID':<8} {'Name':<40} {'Category':<25} {'Severity':<10} {'MITRE'}")
    lines.append("-" * 115)

    events = list(SECURITY_EVENTS.values())
    if category:
        events = [e for e in events if e.qualys_category.lower() == category.lower()]
    if severity:
        events = [e for e in events if e.severity == severity.upper()]

    for event in sorted(events, key=lambda e: e.id):
        mitre = ",".join(event.mitre_techniques[:2])
        if len(event.mitre_techniques) > 2:
            mitre += "..."
        cat_display = event.qualys_category.replace("_", " ")[:24]
        lines.append(f"{event.id:<8} {event.name[:39]:<40} {cat_display:<25} {event.severity:<10} {mitre}")

    lines.append("")
    lines.append(f"Total: {len(events)} events")

    categories = set(e.qualys_category for e in SECURITY_EVENTS.values())
    lines.append(f"\nCategories: {', '.join(sorted(categories))}")

    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Qualys Container Runtime Security Event Catalog")
    parser.add_argument("--list", action="store_true", help="List all events")
    parser.add_argument("--category", help="Filter by Qualys category")
    parser.add_argument("--severity", help="Filter by severity")
    parser.add_argument("--generate", action="store_true", help="Generate all policies")
    parser.add_argument("--action", choices=["Post", "Sigkill"], default="Post")
    parser.add_argument("--output", "-o", default="./event-policies")

    args = parser.parse_args()

    if args.list:
        print(list_events(args.category, args.severity))
    elif args.generate:
        files = generate_all_policies(args.action, args.output)
        print(f"Generated {len(files)} policies in {args.output}")
    else:
        parser.print_help()
