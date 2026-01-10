#!/usr/bin/env python3
"""Generate TracingPolicy YAMLs for all CRS detections."""

import os
import yaml

# All CRS detections with their MITRE mappings and policy definitions
CRS_DETECTIONS = [
    # Initial Access
    {
        "name": "exploit-vsftpd",
        "rule_id": "Exploit_vsftpd_T1190",
        "description": "Detects exploitation of vsftpd vulnerability (CVE-2011-2523)",
        "mitre_technique": "T1190",
        "mitre_tactic": "initial-access",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/sh", "/bash"]},
                ],
                "matchBinaries": [{"operator": "In", "values": ["/vsftpd", "/usr/sbin/vsftpd"]}],
            }]
        }]
    },
    # Credential Access
    {
        "name": "credential-access-bash-history",
        "rule_id": "Credential_access_bash_history_T1552_003",
        "description": "Detect access to bash history files containing credentials",
        "mitre_technique": "T1552.003",
        "mitre_tactic": "credential-access",
        "severity": "high",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Postfix", "values": [
                    "/.bash_history", "/.zsh_history", "/.sh_history"
                ]}],
            }]
        }]
    },
    {
        "name": "cloud-credentials-imds",
        "rule_id": "Cloud_Credentials_accessed_by_network_utility_T1552_005",
        "description": "Detect network utilities accessing cloud instance metadata",
        "mitre_technique": "T1552.005",
        "mitre_tactic": "credential-access",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_connect",
            "syscall": True,
            "args": [{"index": 1, "type": "sockaddr"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "SAddr", "values": ["169.254.169.254"]}],
                "matchBinaries": [{"operator": "In", "values": [
                    "/usr/bin/curl", "/usr/bin/wget", "/usr/bin/fetch"
                ]}],
            }]
        }]
    },
    {
        "name": "find-aws-credentials",
        "rule_id": "Find_AWS_Credentials_T1552_001",
        "description": "Detect searching for AWS credential files",
        "mitre_technique": "T1552.001",
        "mitre_tactic": "credential-access",
        "severity": "high",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Postfix", "values": [
                    "/.aws/credentials", "/.aws/config", "/credentials.json"
                ]}],
            }]
        }]
    },
    {
        "name": "search-private-keys",
        "rule_id": "Search_Private_Keys_or_Passwords_T1552_001",
        "description": "Detect searching for private keys or password files",
        "mitre_technique": "T1552.001",
        "mitre_tactic": "credential-access",
        "severity": "high",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Postfix", "values": [
                    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
                    "/etc/shadow", "/etc/passwd"
                ]}],
            }]
        }]
    },
    # Execution
    {
        "name": "cryptominer-execution",
        "rule_id": "CryptoMiner_Execution_T1496",
        "description": "Detect crypto miner process execution",
        "mitre_technique": "T1496",
        "mitre_tactic": "impact",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/xmrig", "/minerd", "/cpuminer", "/cgminer", "/bfgminer",
                    "/ethminer", "/nbminer", "/t-rex", "/gminer", "/phoenixminer"
                ]}],
            }]
        }, {
            "call": "sys_connect",
            "syscall": True,
            "args": [{"index": 1, "type": "sockaddr"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "DPort", "values": [
                    "3333", "4444", "5555", "7777", "8888", "9999",
                    "14433", "14444", "45700"
                ]}],
            }]
        }]
    },
    {
        "name": "netcat-reverse-shell",
        "rule_id": "Netcat_Reverse_Shell_Execution_T1059_004",
        "description": "Detect netcat reverse shell execution",
        "mitre_technique": "T1059.004",
        "mitre_tactic": "execution",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/nc", "/netcat", "/ncat"]},
                    {"index": 1, "operator": "Contains", "values": ["-e", "-c"]},
                ],
            }]
        }]
    },
    {
        "name": "interactive-shell-container",
        "rule_id": "Interactive_shell_spawned_in_container_T1609",
        "description": "Detect interactive shell spawned in container",
        "mitre_technique": "T1609",
        "mitre_tactic": "execution",
        "severity": "medium",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/sh", "/bash", "/zsh", "/dash"]},
                    {"index": 1, "operator": "Contains", "values": ["-i"]},
                ],
            }]
        }]
    },
    {
        "name": "python-suspicious-args",
        "rule_id": "Python_executed_with_suspicious_arguments_T1059_006",
        "description": "Detect Python with suspicious arguments",
        "mitre_technique": "T1059.006",
        "mitre_tactic": "execution",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/python", "/python3", "/python2"]},
                    {"index": 1, "operator": "Contains", "values": [
                        "socket", "subprocess", "pty.spawn", "base64",
                        "exec(", "eval(", "import os"
                    ]},
                ],
            }]
        }]
    },
    {
        "name": "process-exec-from-memory",
        "rule_id": "Process_exec_from_memory_T1106",
        "description": "Detect process execution from memory (memfd)",
        "mitre_technique": "T1106",
        "mitre_tactic": "execution",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Prefix", "values": ["/proc/self/fd/", "/dev/fd/"]}],
            }]
        }]
    },
    {
        "name": "container-drift",
        "rule_id": "ContainerDrift_Via_File_Creation_and_Execution_T1059_004",
        "description": "Detect container drift via new file creation and execution",
        "mitre_technique": "T1059.004",
        "mitre_tactic": "execution",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Prefix", "values": ["/tmp/", "/var/tmp/", "/dev/shm/"]}],
            }]
        }]
    },
    # Container Escape
    {
        "name": "container-escape-cgroup",
        "rule_id": "Container_escape_via_cgroup_T1611",
        "description": "Detect container escape via cgroup manipulation",
        "mitre_technique": "T1611",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Prefix", "values": [
                    "/sys/fs/cgroup/", "/proc/1/root/"
                ]}],
            }]
        }]
    },
    {
        "name": "container-escape-runtime-socket",
        "rule_id": "Container_escape_using_runtime_socket_T1611",
        "description": "Detect container escape via runtime socket",
        "mitre_technique": "T1611",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Postfix", "values": [
                    "/docker.sock", "/containerd.sock", "/crio.sock",
                    "/dockershim.sock", "/containerd/containerd.sock"
                ]}],
            }]
        }]
    },
    {
        "name": "container-escape-docker-socket",
        "rule_id": "Container_escape_using_docker_socket_T1611",
        "description": "Detect container escape via mounted docker socket",
        "mitre_technique": "T1611",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_connect",
            "syscall": True,
            "args": [{"index": 1, "type": "sockaddr"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Postfix", "values": ["/var/run/docker.sock"]}],
            }]
        }]
    },
    {
        "name": "debugfs-privileged",
        "rule_id": "Debugfs_Launched_in_Privileged_Container_T1611",
        "description": "Detect debugfs in privileged container",
        "mitre_technique": "T1611",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/debugfs"]}],
            }]
        }]
    },
    # Discovery
    {
        "name": "network-scanning",
        "rule_id": "Network_scanning_utility_T1046",
        "description": "Detect network scanning utility execution",
        "mitre_technique": "T1046",
        "mitre_tactic": "discovery",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/nmap", "/masscan", "/zmap", "/rustscan", "/unicornscan"
                ]}],
            }]
        }, {
            "call": "sys_socket",
            "syscall": True,
            "args": [{"index": 1, "type": "int"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Equal", "values": ["3"]}],  # SOCK_RAW
            }]
        }]
    },
    {
        "name": "network-utility-executed",
        "rule_id": "Network_utility_executed_T1016",
        "description": "Detect network utility execution for discovery",
        "mitre_technique": "T1016",
        "mitre_tactic": "discovery",
        "severity": "medium",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/ifconfig", "/ip", "/netstat", "/ss", "/route", "/arp"
                ]}],
            }]
        }]
    },
    {
        "name": "process-capability-enum",
        "rule_id": "Process_Capability_Enumeration_T1057",
        "description": "Detect process capability enumeration",
        "mitre_technique": "T1057",
        "mitre_tactic": "discovery",
        "severity": "medium",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/capsh", "/getcap", "/getpcaps"]}],
            }]
        }]
    },
    # Privilege Escalation
    {
        "name": "suid-binary-execution",
        "rule_id": "Privilege_Escalation_Via_SUID_Binary_Execution_T1548_001",
        "description": "Detect SUID binary execution for privilege escalation",
        "mitre_technique": "T1548.001",
        "mitre_tactic": "privilege-escalation",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/sudo", "/su", "/doas", "/pkexec"
                ]}],
            }]
        }]
    },
    {
        "name": "sudo-privesc",
        "rule_id": "Sudo_Potential_Privilege_Escalation_T1548_003",
        "description": "Detect potential sudo privilege escalation",
        "mitre_technique": "T1548.003",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/sudo"]},
                    {"index": 1, "operator": "Contains", "values": ["-u root", "EDITOR=", "VISUAL="]},
                ],
            }]
        }]
    },
    {
        "name": "polkit-privesc",
        "rule_id": "Polkit_Local_Privilege_Escalation_T1068",
        "description": "Detect Polkit privilege escalation",
        "mitre_technique": "T1068",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/pkexec"]}],
            }]
        }]
    },
    {
        "name": "cap-sys-admin",
        "rule_id": "CAP_SYS_ADMIN_Assigned_to_Binary",
        "description": "Detect CAP_SYS_ADMIN assigned to binary",
        "mitre_technique": "T1548",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchCapabilities": [{"type": "Effective", "operator": "In", "values": ["CAP_SYS_ADMIN"]}],
            }]
        }]
    },
    {
        "name": "gdb-ptrace-privesc",
        "rule_id": "Privilege_Escalation_via_GDB_CAP_SYS_PTRACE_T1055_T1068",
        "description": "Detect GDB with CAP_SYS_PTRACE for privilege escalation",
        "mitre_technique": "T1055",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/gdb"]}],
                "matchCapabilities": [{"type": "Effective", "operator": "In", "values": ["CAP_SYS_PTRACE"]}],
            }]
        }]
    },
    {
        "name": "insmod-container",
        "rule_id": "Insmod_Executed_In_Container_T1014",
        "description": "Detect insmod execution in container (kernel module loading)",
        "mitre_technique": "T1014",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/insmod", "/modprobe"]}],
            }]
        }]
    },
    # Defense Evasion
    {
        "name": "clear-system-logs",
        "rule_id": "Clear_System_Logs_T1070_002",
        "description": "Detect removal of system logs",
        "mitre_technique": "T1070.002",
        "mitre_tactic": "defense-evasion",
        "severity": "high",
        "kprobes": [{
            "call": "sys_unlinkat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Prefix", "values": [
                    "/var/log/", "/var/log/audit/"
                ]}],
            }]
        }]
    },
    {
        "name": "process-hiding",
        "rule_id": "Process_hiding_T1564",
        "description": "Detect process hiding techniques",
        "mitre_technique": "T1564",
        "mitre_tactic": "defense-evasion",
        "severity": "high",
        "kprobes": [{
            "call": "sys_mount",
            "syscall": True,
            "args": [{"index": 2, "type": "string"}, {"index": 3, "type": "int"}],
            "selectors": [{
                "matchArgs": [{"index": 2, "operator": "Equal", "values": ["proc"]}],
            }]
        }]
    },
    {
        "name": "process-hidden-mount-hidepid",
        "rule_id": "Process_hidden_using_mount_hidepid_T1564",
        "description": "Detect mount with hidepid to hide processes",
        "mitre_technique": "T1564",
        "mitre_tactic": "defense-evasion",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/mount"]},
                    {"index": 1, "operator": "Contains", "values": ["hidepid"]},
                ],
            }]
        }]
    },
    {
        "name": "masquerading",
        "rule_id": "Defense_Evasion_Via_Masquerading_T1036_003",
        "description": "Detect masquerading via renamed binaries",
        "mitre_technique": "T1036.003",
        "mitre_tactic": "defense-evasion",
        "severity": "medium",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Prefix", "values": ["/dev/shm/", "/tmp/."]}],
            }]
        }]
    },
    {
        "name": "rootkit-defense-evasion",
        "rule_id": "Defense_Evasion_via_Rootkit_T1222_002",
        "description": "Detect rootkit-style defense evasion",
        "mitre_technique": "T1222.002",
        "mitre_tactic": "defense-evasion",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Prefix", "values": ["/lib/modules/", "/boot/"]}],
            }]
        }]
    },
    {
        "name": "steganography-tools",
        "rule_id": "Usage_of_Steganografy_tools_T1027_003",
        "description": "Detect usage of steganography tools to hide data",
        "mitre_technique": "T1027.003",
        "mitre_tactic": "defense-evasion",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/steghide", "/stegosuite", "/outguess", "/snow"
                ]}],
            }]
        }]
    },
    {
        "name": "stop-antimalware",
        "rule_id": "Stop_antimalware_process_T1562_001",
        "description": "Detect stopping of antimalware processes",
        "mitre_technique": "T1562.001",
        "mitre_tactic": "defense-evasion",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/kill", "/killall", "/pkill"]},
                    {"index": 1, "operator": "Contains", "values": [
                        "falcon", "crowdstrike", "qualys", "tetragon", "cilium"
                    ]},
                ],
            }]
        }]
    },
    {
        "name": "compiler-in-container",
        "rule_id": "Compiler_executed_in_container_T1027_004",
        "description": "Detect compiler execution in container",
        "mitre_technique": "T1027.004",
        "mitre_tactic": "defense-evasion",
        "severity": "medium",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/gcc", "/g++", "/clang", "/make", "/cmake", "/go"
                ]}],
            }]
        }]
    },
    {
        "name": "curl-socks-proxy",
        "rule_id": "Curl_Using_Socks_Proxy_T1572",
        "description": "Detect curl using SOCKS proxy for tunneling",
        "mitre_technique": "T1572",
        "mitre_tactic": "command-and-control",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/curl"]},
                    {"index": 1, "operator": "Contains", "values": ["--socks", "-x socks"]},
                ],
            }]
        }]
    },
    # Persistence
    {
        "name": "schedule-cron-jobs",
        "rule_id": "Schedule_Cron_Jobs_T1053_003",
        "description": "Detect scheduling of cron jobs for persistence",
        "mitre_technique": "T1053.003",
        "mitre_tactic": "persistence",
        "severity": "high",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}, {"index": 2, "type": "int"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 1, "operator": "Prefix", "values": ["/etc/cron", "/var/spool/cron"]},
                    {"index": 2, "operator": "Mask", "values": ["O_WRONLY", "O_RDWR"]},
                ],
            }]
        }]
    },
    {
        "name": "local-account-password-modified",
        "rule_id": "Local_account_password_modified_T1098_007",
        "description": "Detect local account password modification",
        "mitre_technique": "T1098.007",
        "mitre_tactic": "persistence",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/passwd", "/chpasswd", "/usermod"]}],
            }]
        }]
    },
    {
        "name": "k8s-service-account-token",
        "rule_id": "Kubernetes_service_account_token_created_in_container_T1609",
        "description": "Detect Kubernetes service account token access",
        "mitre_technique": "T1609",
        "mitre_tactic": "persistence",
        "severity": "high",
        "kprobes": [{
            "call": "sys_openat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 1, "operator": "Prefix", "values": [
                    "/var/run/secrets/kubernetes.io/serviceaccount/"
                ]}],
            }]
        }]
    },
    # Lateral Movement
    {
        "name": "remote-file-copy",
        "rule_id": "Launch_Remote_File_Copy_Tools_in_Container_T1021",
        "description": "Detect remote file copy tools in container",
        "mitre_technique": "T1021",
        "mitre_tactic": "lateral-movement",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/ssh", "/scp", "/sftp", "/rsync"
                ]}],
            }]
        }]
    },
    {
        "name": "ingress-file-copy",
        "rule_id": "Launch_Ingress_Remote_File_Copy_Tools_in_Container_T1105",
        "description": "Detect ingress file transfer tools",
        "mitre_technique": "T1105",
        "mitre_tactic": "command-and-control",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/curl", "/wget", "/ftp", "/tftp", "/nc"
                ]}],
            }]
        }]
    },
    {
        "name": "container-management-utility",
        "rule_id": "Container_management_utility_in_container_T1609",
        "description": "Detect container management utilities inside container",
        "mitre_technique": "T1609",
        "mitre_tactic": "execution",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/docker", "/kubectl", "/crictl", "/ctr", "/podman"
                ]}],
            }]
        }]
    },
    {
        "name": "package-manager-container",
        "rule_id": "Package_Management_Process_in_Container_T1505",
        "description": "Detect package manager execution in container",
        "mitre_technique": "T1505",
        "mitre_tactic": "persistence",
        "severity": "medium",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/apt", "/apt-get", "/yum", "/dnf", "/apk", "/pip", "/npm"
                ]}],
            }]
        }]
    },
    # Collection
    {
        "name": "automated-collection",
        "rule_id": "Collection_Via_Automated_Collection_T1119",
        "description": "Detect automated data collection",
        "mitre_technique": "T1119",
        "mitre_tactic": "collection",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/find", "/locate"]},
                    {"index": 1, "operator": "Contains", "values": [
                        ".pem", ".key", "password", "credential", ".ssh"
                    ]},
                ],
            }]
        }]
    },
    {
        "name": "network-traffic-capture",
        "rule_id": "Network_Traffic_Capture_via_CAP_NET_RAW_T1040",
        "description": "Detect network traffic capture",
        "mitre_technique": "T1040",
        "mitre_tactic": "collection",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/tcpdump", "/tshark", "/wireshark", "/dumpcap"
                ]}],
            }]
        }]
    },
    # Exploitation
    {
        "name": "gdb-container",
        "rule_id": "GDB_Executed_In_Container_T1055",
        "description": "Detect GDB execution in container for process injection",
        "mitre_technique": "T1055",
        "mitre_tactic": "privilege-escalation",
        "severity": "high",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/gdb", "/lldb", "/strace"]}],
            }]
        }]
    },
    {
        "name": "db-program-spawned",
        "rule_id": "DB_program_spawned_process_T1210",
        "description": "Detect database program spawning shell",
        "mitre_technique": "T1210",
        "mitre_tactic": "lateral-movement",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": ["/sh", "/bash"]}],
                "matchBinaries": [{"operator": "In", "values": [
                    "/usr/bin/mysql", "/usr/bin/psql", "/usr/bin/mongo",
                    "/usr/bin/redis-cli", "/usr/bin/sqlite3"
                ]}],
            }]
        }]
    },
    # Additional Missing Rules from CRS Document
    {
        "name": "command-line-interface-execution",
        "rule_id": "Execution_Via_Command_Line_Interface_T1059_004",
        "description": "Detect command line interface execution for shell commands",
        "mitre_technique": "T1059.004",
        "mitre_tactic": "execution",
        "severity": "medium",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "string"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Postfix", "values": ["/sh", "/bash", "/zsh", "/dash", "/ash"]},
                    {"index": 1, "operator": "Contains", "values": ["-c"]},
                ],
            }]
        }]
    },
    {
        "name": "enlightenment-privesc",
        "rule_id": "Potential_Privilege_Escalation_via_Enlightenment_T1068",
        "description": "Detect privilege escalation via Enlightenment window manager vulnerabilities",
        "mitre_technique": "T1068",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{"index": 0, "operator": "Postfix", "values": [
                    "/enlightenment_sys", "/enlightenment_system"
                ]}],
            }]
        }]
    },
    {
        "name": "linux-dac-privesc",
        "rule_id": "Potential_Privilege_Escalation_via_Linux_DAC_permissions_T1068",
        "description": "Detect privilege escalation via Linux DAC permission manipulation",
        "mitre_technique": "T1068",
        "mitre_tactic": "privilege-escalation",
        "severity": "high",
        "kprobes": [{
            "call": "sys_chmod",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "int"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Prefix", "values": ["/etc/", "/usr/bin/", "/usr/sbin/"]},
                    {"index": 1, "operator": "Mask", "values": ["4755", "4777", "6755"]},  # SUID/SGID bits
                ],
            }]
        }, {
            "call": "sys_fchmodat",
            "syscall": True,
            "args": [{"index": 1, "type": "string"}, {"index": 2, "type": "int"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 1, "operator": "Prefix", "values": ["/etc/", "/usr/bin/", "/usr/sbin/"]},
                ],
            }]
        }]
    },
    {
        "name": "cap-chown-fowner-privesc",
        "rule_id": "Privilege_Escalation_via_CAP_CHOWN_CAP_FOWNER_Capabilities_T1068",
        "description": "Detect privilege escalation via CAP_CHOWN or CAP_FOWNER capabilities",
        "mitre_technique": "T1068",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchCapabilities": [{"type": "Effective", "operator": "In", "values": [
                    "CAP_CHOWN", "CAP_FOWNER"
                ]}],
            }]
        }, {
            "call": "sys_chown",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}, {"index": 1, "type": "int"}, {"index": 2, "type": "int"}],
            "selectors": [{
                "matchArgs": [
                    {"index": 0, "operator": "Prefix", "values": ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]},
                ],
            }]
        }]
    },
    {
        "name": "process-capabilities-privesc",
        "rule_id": "Privilege_Escalation_Via_Process_Capabilities_T1548",
        "description": "Detect privilege escalation via process capabilities",
        "mitre_technique": "T1548",
        "mitre_tactic": "privilege-escalation",
        "severity": "critical",
        "kprobes": [{
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchCapabilities": [{"type": "Effective", "operator": "In", "values": [
                    "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"
                ]}],
            }]
        }]
    },
]


def generate_policy(detection, action="Post"):
    """Generate a TracingPolicy from a detection definition."""
    name = f"crs-{detection['name']}"

    # Build kprobes with action
    kprobes = []
    for kp in detection.get("kprobes", []):
        kprobe = {
            "call": kp["call"],
            "syscall": kp.get("syscall", True),
            "args": kp.get("args", []),
            "selectors": [],
        }

        for sel in kp.get("selectors", []):
            selector = dict(sel)
            selector["matchActions"] = [{"action": action}]
            kprobe["selectors"].append(selector)

        kprobes.append(kprobe)

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": name,
            "labels": {
                "generated-by": "qualys-crs",
                "qualys.com/rule-id": detection["rule_id"],
                "mitre.attack/technique": detection["mitre_technique"],
                "mitre.attack/tactic": detection["mitre_tactic"],
                "policy.qualys.com/severity": detection["severity"],
            },
            "annotations": {
                "description": detection["description"],
            },
        },
        "spec": {
            "kprobes": kprobes,
        },
    }

    return policy


def main():
    output_dir = os.path.dirname(os.path.abspath(__file__))

    # Generate detection policies (audit mode)
    detection_dir = os.path.join(output_dir, "detection")
    os.makedirs(detection_dir, exist_ok=True)

    # Generate prevention policies (block mode)
    prevention_dir = os.path.join(output_dir, "prevention")
    os.makedirs(prevention_dir, exist_ok=True)

    print(f"Generating {len(CRS_DETECTIONS)} CRS detection policies...\n")

    for detection in CRS_DETECTIONS:
        # Detection policy (audit)
        policy = generate_policy(detection, action="Post")
        filename = f"{detection['name']}.yaml"

        with open(os.path.join(detection_dir, filename), "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

        # Prevention policy (block)
        policy = generate_policy(detection, action="Sigkill")
        policy["metadata"]["name"] = f"crs-block-{detection['name']}"
        policy["metadata"]["labels"]["policy.qualys.com/action"] = "block"

        with open(os.path.join(prevention_dir, filename), "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

        print(f"  {detection['name']}: {detection['mitre_technique']} ({detection['severity']})")

    print(f"\nGenerated {len(CRS_DETECTIONS)} detection policies in {detection_dir}")
    print(f"Generated {len(CRS_DETECTIONS)} prevention policies in {prevention_dir}")

    # Generate summary
    tactics = {}
    for d in CRS_DETECTIONS:
        tactic = d["mitre_tactic"]
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(d)

    print("\n=== Summary by MITRE Tactic ===")
    for tactic, detections in sorted(tactics.items()):
        print(f"\n{tactic.upper()} ({len(detections)} rules):")
        for d in detections:
            print(f"  - {d['name']}: {d['mitre_technique']}")


if __name__ == "__main__":
    main()
