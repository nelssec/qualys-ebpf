"""Policy generator for Tetragon TracingPolicy and Qualys FimPolicy CRDs."""
import yaml
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from config import PolicyConfig, MITRE_TECHNIQUES, THREAT_INDICATORS


@dataclass
class KprobeSpec:
    """Specification for a kprobe in TracingPolicy."""
    call: str
    syscall: bool = True
    args: List[Dict[str, Any]] = field(default_factory=list)
    selectors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class TracingPolicy:
    """Tetragon TracingPolicy CRD representation."""
    name: str
    labels: Dict[str, str]
    kprobes: List[KprobeSpec]
    namespace: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Kubernetes CRD dictionary."""
        spec = {"kprobes": []}

        for kprobe in self.kprobes:
            kprobe_dict = {
                "call": kprobe.call,
                "syscall": kprobe.syscall,
            }
            if kprobe.args:
                kprobe_dict["args"] = kprobe.args
            if kprobe.selectors:
                kprobe_dict["selectors"] = kprobe.selectors
            spec["kprobes"].append(kprobe_dict)

        policy = {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy" if not self.namespace else "TracingPolicyNamespaced",
            "metadata": {
                "name": self.name,
                "labels": self.labels,
            },
            "spec": spec,
        }

        if self.namespace:
            policy["metadata"]["namespace"] = self.namespace

        return policy

    def to_yaml(self) -> str:
        """Convert to YAML string."""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)


@dataclass
class FimPolicy:
    """Qualys FimPolicy CRD representation."""
    name: str
    base_policy: str  # file-open, file-read, file-write, file-write-diff, file-rename, file-delete
    action: str = "audit"
    monitor_paths: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Kubernetes CRD dictionary."""
        return {
            "apiVersion": "qualys.com/v1",
            "kind": "FimPolicy",
            "metadata": {
                "name": self.name,
                "labels": self.labels,
            },
            "spec": {
                "base-policy": self.base_policy,
                "action": self.action,
                "monitor-paths": self.monitor_paths,
            },
        }

    def to_yaml(self) -> str:
        """Convert to YAML string."""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)


class PolicyGenerator:
    """Generator for creating security policies from various inputs."""

    def __init__(self, config: PolicyConfig):
        self.config = config

    def generate_execve_policy(self,
                               name: str,
                               binaries: List[str],
                               action: str = "Post",
                               mitre_technique: Optional[str] = None,
                               category: str = "execution") -> TracingPolicy:
        """
        Generate a TracingPolicy for monitoring/blocking binary execution.

        Args:
            name: Policy name
            binaries: List of binary paths/suffixes to match
            action: Action to take (Post, Sigkill, etc.)
            mitre_technique: MITRE ATT&CK technique ID
            category: Threat category

        Returns:
            TracingPolicy object
        """
        labels = {
            "app.kubernetes.io/name": "qualys-threat-detection",
            "threat.qualys.com/category": category,
        }

        if mitre_technique and self.config.include_mitre_tags:
            if mitre_technique in MITRE_TECHNIQUES:
                labels["mitre.attack/tactic"] = MITRE_TECHNIQUES[mitre_technique]["tactic"]
                labels["mitre.attack/technique"] = mitre_technique

        selector = {
            "matchArgs": [{
                "index": 0,
                "operator": "Postfix",
                "values": binaries,
            }],
            "matchActions": [{"action": action}],
        }

        if action == "Post" and self.config.rate_limit:
            selector["matchActions"][0]["rateLimit"] = self.config.rate_limit

        kprobe = KprobeSpec(
            call="sys_execve",
            syscall=True,
            args=[{"index": 0, "type": "string"}],
            selectors=[selector],
        )

        return TracingPolicy(
            name=name,
            labels=labels,
            kprobes=[kprobe],
            namespace=self.config.namespace,
        )

    def generate_file_access_policy(self,
                                    name: str,
                                    file_paths: List[str],
                                    match_type: str = "Prefix",
                                    write_only: bool = False,
                                    action: str = "Post",
                                    mitre_technique: Optional[str] = None,
                                    category: str = "file-access") -> TracingPolicy:
        """
        Generate a TracingPolicy for monitoring/blocking file access.

        Args:
            name: Policy name
            file_paths: List of file paths to match
            match_type: Match operator (Equal, Prefix, Postfix)
            write_only: Only match write operations
            action: Action to take
            mitre_technique: MITRE ATT&CK technique ID
            category: Threat category

        Returns:
            TracingPolicy object
        """
        labels = {
            "app.kubernetes.io/name": "qualys-threat-detection",
            "threat.qualys.com/category": category,
        }

        if mitre_technique and self.config.include_mitre_tags:
            if mitre_technique in MITRE_TECHNIQUES:
                labels["mitre.attack/tactic"] = MITRE_TECHNIQUES[mitre_technique]["tactic"]
                labels["mitre.attack/technique"] = mitre_technique

        match_args = [{
            "index": 1,
            "operator": match_type,
            "values": file_paths,
        }]

        if write_only:
            match_args.append({
                "index": 2,
                "operator": "Mask",
                "values": ["2"],  # O_RDWR or write flag
            })

        selector = {
            "matchArgs": match_args,
            "matchActions": [{"action": action}],
        }

        args = [
            {"index": 1, "type": "string"},
        ]
        if write_only:
            args.append({"index": 2, "type": "int"})

        kprobe = KprobeSpec(
            call="sys_openat",
            syscall=True,
            args=args,
            selectors=[selector],
        )

        return TracingPolicy(
            name=name,
            labels=labels,
            kprobes=[kprobe],
            namespace=self.config.namespace,
        )

    def generate_network_policy(self,
                                name: str,
                                ports: List[int],
                                action: str = "Post",
                                mitre_technique: Optional[str] = None,
                                category: str = "network") -> TracingPolicy:
        """
        Generate a TracingPolicy for monitoring/blocking network connections.

        Args:
            name: Policy name
            ports: List of destination ports to match
            action: Action to take
            mitre_technique: MITRE ATT&CK technique ID
            category: Threat category

        Returns:
            TracingPolicy object
        """
        labels = {
            "app.kubernetes.io/name": "qualys-threat-detection",
            "threat.qualys.com/category": category,
        }

        if mitre_technique and self.config.include_mitre_tags:
            if mitre_technique in MITRE_TECHNIQUES:
                labels["mitre.attack/tactic"] = MITRE_TECHNIQUES[mitre_technique]["tactic"]
                labels["mitre.attack/technique"] = mitre_technique

        selector = {
            "matchArgs": [{
                "index": 1,
                "operator": "DPort",
                "values": [str(p) for p in ports],
            }],
            "matchActions": [{"action": action}],
        }

        kprobe = KprobeSpec(
            call="sys_connect",
            syscall=True,
            args=[{"index": 1, "type": "sockaddr"}],
            selectors=[selector],
        )

        return TracingPolicy(
            name=name,
            labels=labels,
            kprobes=[kprobe],
            namespace=self.config.namespace,
        )

    def generate_syscall_policy(self,
                                name: str,
                                syscall: str,
                                args: List[Dict[str, Any]],
                                selectors: List[Dict[str, Any]],
                                action: str = "Post",
                                mitre_technique: Optional[str] = None,
                                category: str = "syscall") -> TracingPolicy:
        """
        Generate a generic syscall TracingPolicy.

        Args:
            name: Policy name
            syscall: Syscall name (e.g., sys_ptrace)
            args: List of argument specifications
            selectors: List of selector specifications
            action: Action to take
            mitre_technique: MITRE ATT&CK technique ID
            category: Threat category

        Returns:
            TracingPolicy object
        """
        labels = {
            "app.kubernetes.io/name": "qualys-threat-detection",
            "threat.qualys.com/category": category,
        }

        if mitre_technique and self.config.include_mitre_tags:
            if mitre_technique in MITRE_TECHNIQUES:
                labels["mitre.attack/tactic"] = MITRE_TECHNIQUES[mitre_technique]["tactic"]
                labels["mitre.attack/technique"] = mitre_technique

        # Add action to selectors if not present
        for selector in selectors:
            if "matchActions" not in selector:
                selector["matchActions"] = [{"action": action}]

        kprobe = KprobeSpec(
            call=syscall,
            syscall=True,
            args=args,
            selectors=selectors,
        )

        return TracingPolicy(
            name=name,
            labels=labels,
            kprobes=[kprobe],
            namespace=self.config.namespace,
        )

    def generate_fim_policy(self,
                            name: str,
                            paths: List[str],
                            operation: str = "file-write",
                            category: str = "integrity-monitoring") -> FimPolicy:
        """
        Generate a Qualys FimPolicy for file integrity monitoring.

        Args:
            name: Policy name
            paths: List of paths to monitor
            operation: File operation to monitor
            category: Threat category

        Returns:
            FimPolicy object
        """
        return FimPolicy(
            name=name,
            base_policy=operation,
            action="audit",
            monitor_paths=paths,
            labels={
                "app.kubernetes.io/name": "qualys-fim",
                "threat.qualys.com/category": category,
            },
        )

    def generate_from_threat_indicators(self, indicators: List[Dict]) -> List[TracingPolicy]:
        """
        Generate policies from Qualys threat indicators.

        Args:
            indicators: List of threat indicator dictionaries

        Returns:
            List of TracingPolicy objects
        """
        policies = []

        for indicator in indicators:
            if not indicator.get("mitre_techniques"):
                continue

            for technique in indicator["mitre_techniques"]:
                # Map technique to policy type
                if technique.startswith("T1059"):
                    # Command execution - generate execve policy
                    policy = self.generate_execve_policy(
                        name=f"detect-{indicator['qid']}-exec",
                        binaries=THREAT_INDICATORS["reverse_shells"]["binaries"],
                        action="Post" if not self.config.enforcement_mode else "Sigkill",
                        mitre_technique=technique,
                        category="execution",
                    )
                    policies.append(policy)

                elif technique.startswith("T1552"):
                    # Credential access - generate file access policy
                    all_cred_files = (
                        THREAT_INDICATORS["credential_files"]["linux"] +
                        THREAT_INDICATORS["credential_files"]["ssh"] +
                        THREAT_INDICATORS["credential_files"]["cloud"]
                    )
                    policy = self.generate_file_access_policy(
                        name=f"detect-{indicator['qid']}-creds",
                        file_paths=all_cred_files,
                        match_type="Postfix",
                        action="Post",
                        mitre_technique=technique,
                        category="credential-access",
                    )
                    policies.append(policy)

        return policies

    def save_policy(self, policy, output_dir: Optional[str] = None) -> str:
        """
        Save a policy to a YAML file.

        Args:
            policy: TracingPolicy or FimPolicy object
            output_dir: Optional output directory override

        Returns:
            Path to saved file
        """
        out_dir = output_dir or self.config.output_dir
        os.makedirs(out_dir, exist_ok=True)

        filename = f"{policy.name}.yaml"
        filepath = os.path.join(out_dir, filename)

        with open(filepath, "w") as f:
            f.write(policy.to_yaml())

        return filepath

    def save_policies(self,
                      policies: List,
                      output_dir: Optional[str] = None,
                      single_file: bool = False) -> List[str]:
        """
        Save multiple policies to YAML files.

        Args:
            policies: List of policy objects
            output_dir: Optional output directory override
            single_file: Combine all policies into single file

        Returns:
            List of paths to saved files
        """
        out_dir = output_dir or self.config.output_dir
        os.makedirs(out_dir, exist_ok=True)

        if single_file:
            filepath = os.path.join(out_dir, "all-policies.yaml")
            with open(filepath, "w") as f:
                for i, policy in enumerate(policies):
                    if i > 0:
                        f.write("---\n")
                    f.write(policy.to_yaml())
            return [filepath]

        paths = []
        for policy in policies:
            path = self.save_policy(policy, out_dir)
            paths.append(path)

        return paths
