"""Configuration for Qualys policy generator."""
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class QualysConfig:
    """Qualys API configuration."""
    api_url: str
    username: str
    password: str

    @classmethod
    def from_env(cls) -> "QualysConfig":
        """Load configuration from environment variables."""
        return cls(
            api_url=os.environ.get("QUALYS_API_URL", "https://qualysapi.qualys.com"),
            username=os.environ.get("QUALYS_USERNAME", ""),
            password=os.environ.get("QUALYS_PASSWORD", ""),
        )


@dataclass
class PolicyConfig:
    """Policy generation configuration."""
    output_dir: str = "./generated-policies"
    namespace: Optional[str] = None
    enforcement_mode: bool = False  # True = Sigkill, False = Post (audit)
    include_mitre_tags: bool = True
    rate_limit: str = "1m"


# MITRE ATT&CK technique mappings
MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege-escalation"},
    "T1548.001": {"name": "Setuid and Setgid", "tactic": "privilege-escalation"},
    "T1611": {"name": "Escape to Host", "tactic": "privilege-escalation"},
    "T1496": {"name": "Resource Hijacking", "tactic": "impact"},
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement"},
    "T1021.004": {"name": "SSH", "tactic": "lateral-movement"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "credential-access"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "credential-access"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "persistence"},
    "T1053.003": {"name": "Cron", "tactic": "persistence"},
    "T1505.003": {"name": "Web Shell", "tactic": "persistence"},
    "T1547.006": {"name": "Kernel Modules and Extensions", "tactic": "persistence"},
    "T1222": {"name": "File and Directory Permissions Modification", "tactic": "defense-evasion"},
}

# Common threat indicators for detection
THREAT_INDICATORS = {
    "reverse_shells": {
        "binaries": ["/nc", "/ncat", "/netcat", "/socat"],
        "shell_binaries": ["/bash", "/sh", "/zsh", "/dash", "/ash"],
        "scripting": ["/python", "/python3", "/perl", "/ruby", "/php"],
    },
    "crypto_miners": {
        "binaries": ["xmrig", "xmr-stak", "minerd", "cpuminer", "cgminer",
                     "bfgminer", "ethminer", "ccminer", "nheqminer"],
        "ports": [3333, 4444, 5555, 7777, 14433, 14444, 45700],
    },
    "recon_tools": {
        "binaries": ["/nmap", "/masscan", "/zmap", "/netdiscover", "/arp-scan"],
    },
    "credential_files": {
        "linux": ["/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/sudoers"],
        "ssh": ["/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/authorized_keys"],
        "cloud": ["/.aws/credentials", "/.azure/credentials", "/.kube/config"],
    },
    "persistence_paths": {
        "cron": ["/etc/cron.d", "/etc/crontab", "/var/spool/cron"],
        "systemd": ["/etc/systemd/system", "/usr/lib/systemd/system"],
        "init": ["/etc/init.d", "/etc/rc.d", "/etc/rc.local"],
    },
}
