#!/usr/bin/env python3
"""Container Drift Management for Qualys CRS.

Drift detection and prevention policies that enforce container immutability
by blocking execution of binaries not present in the original image.
"""
import os
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class DriftPolicy:
    """Configuration for drift prevention policy."""
    name: str
    description: str
    mode: str  # "detect" or "enforce"
    allowed_paths: List[str] = field(default_factory=list)
    blocked_paths: List[str] = field(default_factory=list)
    namespace_selector: Optional[Dict[str, str]] = None
    pod_selector: Optional[Dict[str, str]] = None


DEFAULT_MUTABLE_PATHS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
    "/var/run",
    "/var/cache",
    "/proc",
    "/sys",
]

DEFAULT_BLOCKED_WRITE_PATHS = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/opt",
]

RUNTIME_BLOCK_BINARIES = [
    "/apt",
    "/apt-get",
    "/yum",
    "/dnf",
    "/apk",
    "/pip",
    "/pip3",
    "/npm",
    "/yarn",
    "/gem",
    "/cargo",
    "/go",
    "/curl",
    "/wget",
]


def generate_drift_detection_policy(
    name: str = "qcr-drift-detection",
    namespace: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a TracingPolicy that detects container drift (new executables)."""
    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": name,
            "labels": {
                "qualys.com/policy-type": "drift-detection",
                "qualys.com/category": "container-immutability",
                "app.kubernetes.io/managed-by": "qualys-crs",
            },
            "annotations": {
                "qualys.com/description": "Detects creation of new executable files in running containers",
                "qualys.com/mitre-techniques": "T1036,T1027",
            },
        },
        "spec": {
            "kprobes": [
                {
                    "call": "sys_openat",
                    "syscall": True,
                    "args": [
                        {"index": 1, "type": "string"},
                        {"index": 2, "type": "int"},
                    ],
                    "selectors": [{
                        "matchArgs": [
                            {
                                "index": 1,
                                "operator": "Prefix",
                                "values": ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/"],
                            },
                            {
                                "index": 2,
                                "operator": "Mask",
                                "values": ["64"],  # O_CREAT flag
                            },
                        ],
                        "matchActions": [{"action": "Post"}],
                    }],
                },
                {
                    "call": "sys_chmod",
                    "syscall": True,
                    "args": [
                        {"index": 0, "type": "string"},
                        {"index": 1, "type": "int"},
                    ],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 1,
                            "operator": "Mask",
                            "values": ["73"],  # Execute bits (111 octal = 73 decimal)
                        }],
                        "matchActions": [{"action": "Post"}],
                    }],
                },
                {
                    "call": "sys_fchmod",
                    "syscall": True,
                    "args": [
                        {"index": 0, "type": "int"},
                        {"index": 1, "type": "int"},
                    ],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 1,
                            "operator": "Mask",
                            "values": ["73"],
                        }],
                        "matchActions": [{"action": "Post"}],
                    }],
                },
                {
                    "call": "sys_fchmodat",
                    "syscall": True,
                    "args": [
                        {"index": 1, "type": "string"},
                        {"index": 2, "type": "int"},
                    ],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 2,
                            "operator": "Mask",
                            "values": ["73"],
                        }],
                        "matchActions": [{"action": "Post"}],
                    }],
                },
            ],
        },
    }

    if namespace:
        policy["spec"]["podSelector"] = {
            "matchLabels": {},
            "namespace": namespace,
        }

    return policy


def generate_drift_enforcement_policy(
    name: str = "qcr-drift-enforcement",
    namespace: Optional[str] = None,
    allowed_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generate a TracingPolicy that blocks drift (new executables are killed)."""
    allowed = allowed_paths or []

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": name,
            "labels": {
                "qualys.com/policy-type": "drift-enforcement",
                "qualys.com/category": "container-immutability",
                "app.kubernetes.io/managed-by": "qualys-crs",
            },
            "annotations": {
                "qualys.com/description": "Blocks execution of binaries created after container start",
                "qualys.com/mitre-techniques": "T1036,T1027",
            },
        },
        "spec": {
            "kprobes": [
                {
                    "call": "sys_execve",
                    "syscall": True,
                    "args": [{"index": 0, "type": "string"}],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 0,
                            "operator": "Prefix",
                            "values": ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"],
                        }],
                        "matchActions": [{"action": "Sigkill"}],
                    }],
                },
            ],
        },
    }

    if namespace:
        policy["spec"]["podSelector"] = {
            "matchLabels": {},
            "namespace": namespace,
        }

    return policy


def generate_binary_path_enforcement_policy(
    name: str = "qcr-binary-path-enforcement",
    namespace: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate policy that blocks writes to system binary directories."""
    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": name,
            "labels": {
                "qualys.com/policy-type": "binary-path-protection",
                "qualys.com/category": "container-immutability",
                "app.kubernetes.io/managed-by": "qualys-crs",
            },
            "annotations": {
                "qualys.com/description": "Blocks write operations to system binary directories",
                "qualys.com/blocked-paths": ",".join(DEFAULT_BLOCKED_WRITE_PATHS[:5]),
            },
        },
        "spec": {
            "kprobes": [
                {
                    "call": "sys_openat",
                    "syscall": True,
                    "args": [
                        {"index": 1, "type": "string"},
                        {"index": 2, "type": "int"},
                    ],
                    "selectors": [{
                        "matchArgs": [
                            {
                                "index": 1,
                                "operator": "Prefix",
                                "values": DEFAULT_BLOCKED_WRITE_PATHS,
                            },
                            {
                                "index": 2,
                                "operator": "Mask",
                                "values": ["1", "2", "64"],  # O_WRONLY, O_RDWR, O_CREAT
                            },
                        ],
                        "matchActions": [{"action": "Sigkill"}],
                    }],
                },
                {
                    "call": "sys_rename",
                    "syscall": True,
                    "args": [
                        {"index": 0, "type": "string"},
                        {"index": 1, "type": "string"},
                    ],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 1,
                            "operator": "Prefix",
                            "values": DEFAULT_BLOCKED_WRITE_PATHS,
                        }],
                        "matchActions": [{"action": "Sigkill"}],
                    }],
                },
                {
                    "call": "sys_unlink",
                    "syscall": True,
                    "args": [{"index": 0, "type": "string"}],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 0,
                            "operator": "Prefix",
                            "values": DEFAULT_BLOCKED_WRITE_PATHS,
                        }],
                        "matchActions": [{"action": "Sigkill"}],
                    }],
                },
            ],
        },
    }

    return policy


def generate_package_manager_block_policy(
    name: str = "qcr-block-package-managers",
    namespace: Optional[str] = None,
    mode: str = "enforce",
) -> Dict[str, Any]:
    """Generate policy that blocks package manager execution in runtime containers."""
    action = "Sigkill" if mode == "enforce" else "Post"

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": name,
            "labels": {
                "qualys.com/policy-type": "package-manager-block",
                "qualys.com/category": "container-immutability",
                "qualys.com/mode": mode,
                "app.kubernetes.io/managed-by": "qualys-crs",
            },
            "annotations": {
                "qualys.com/description": "Blocks package manager and download tool execution in production",
                "qualys.com/mitre-techniques": "T1059,T1105",
            },
        },
        "spec": {
            "kprobes": [{
                "call": "sys_execve",
                "syscall": True,
                "args": [
                    {"index": 0, "type": "string"},
                    {"index": 1, "type": "string"},
                ],
                "selectors": [{
                    "matchArgs": [{
                        "index": 0,
                        "operator": "Postfix",
                        "values": RUNTIME_BLOCK_BINARIES,
                    }],
                    "matchActions": [{"action": action}],
                }],
            }],
        },
    }

    return policy


def generate_download_tool_block_policy(
    name: str = "qcr-block-download-tools",
    namespace: Optional[str] = None,
    mode: str = "enforce",
) -> Dict[str, Any]:
    """Generate policy that blocks common download/transfer tools."""
    action = "Sigkill" if mode == "enforce" else "Post"

    policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": name,
            "labels": {
                "qualys.com/policy-type": "download-tool-block",
                "qualys.com/category": "container-immutability",
                "qualys.com/mode": mode,
                "app.kubernetes.io/managed-by": "qualys-crs",
            },
            "annotations": {
                "qualys.com/description": "Blocks file download and transfer tools in production containers",
            },
        },
        "spec": {
            "kprobes": [{
                "call": "sys_execve",
                "syscall": True,
                "args": [{"index": 0, "type": "string"}],
                "selectors": [{
                    "matchArgs": [{
                        "index": 0,
                        "operator": "Postfix",
                        "values": [
                            "/curl", "/wget", "/fetch", "/aria2c",
                            "/scp", "/sftp", "/rsync", "/ftp",
                        ],
                    }],
                    "matchActions": [{"action": action}],
                }],
            }],
        },
    }

    return policy


def generate_full_drift_policy_set(
    output_dir: str,
    mode: str = "detect",
    namespace: Optional[str] = None,
) -> List[str]:
    """Generate complete set of drift management policies."""
    os.makedirs(output_dir, exist_ok=True)
    files = []

    if mode == "detect":
        policy = generate_drift_detection_policy(namespace=namespace)
        filepath = os.path.join(output_dir, "drift-detection.yaml")
        with open(filepath, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        files.append(filepath)

        policy = generate_package_manager_block_policy(mode="detect", namespace=namespace)
        filepath = os.path.join(output_dir, "package-manager-detect.yaml")
        with open(filepath, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        files.append(filepath)

    elif mode == "enforce":
        policy = generate_drift_enforcement_policy(namespace=namespace)
        filepath = os.path.join(output_dir, "drift-enforcement.yaml")
        with open(filepath, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        files.append(filepath)

        policy = generate_binary_path_enforcement_policy(namespace=namespace)
        filepath = os.path.join(output_dir, "binary-path-enforcement.yaml")
        with open(filepath, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        files.append(filepath)

        policy = generate_package_manager_block_policy(mode="enforce", namespace=namespace)
        filepath = os.path.join(output_dir, "package-manager-block.yaml")
        with open(filepath, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        files.append(filepath)

        policy = generate_download_tool_block_policy(mode="enforce", namespace=namespace)
        filepath = os.path.join(output_dir, "download-tool-block.yaml")
        with open(filepath, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        files.append(filepath)

    return files


def list_drift_policies() -> str:
    """List available drift management policies."""
    lines = []
    lines.append("Qualys CRS Drift Management Policies")
    lines.append("=" * 50)
    lines.append("")
    lines.append("DETECTION MODE (--mode detect):")
    lines.append("  - drift-detection: Alerts on new executable creation")
    lines.append("  - package-manager-detect: Alerts on package manager usage")
    lines.append("")
    lines.append("ENFORCEMENT MODE (--mode enforce):")
    lines.append("  - drift-enforcement: Blocks execution from temp directories")
    lines.append("  - binary-path-enforcement: Blocks writes to /bin, /usr/bin, etc.")
    lines.append("  - package-manager-block: Kills package manager processes")
    lines.append("  - download-tool-block: Kills download tools (curl, wget)")
    lines.append("")
    lines.append("PROTECTED PATHS:")
    for path in DEFAULT_BLOCKED_WRITE_PATHS:
        lines.append(f"  {path}")
    lines.append("")
    lines.append("BLOCKED BINARIES (runtime):")
    for binary in RUNTIME_BLOCK_BINARIES:
        lines.append(f"  {binary}")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Qualys CRS Drift Management")
    parser.add_argument("--list", action="store_true", help="List drift policies")
    parser.add_argument("--generate", action="store_true", help="Generate drift policies")
    parser.add_argument("--mode", choices=["detect", "enforce"], default="detect",
                        help="Policy mode: detect (alert) or enforce (block)")
    parser.add_argument("--namespace", "-n", help="Kubernetes namespace")
    parser.add_argument("--output", "-o", default="./drift-policies", help="Output directory")

    args = parser.parse_args()

    if args.list:
        print(list_drift_policies())
    elif args.generate:
        files = generate_full_drift_policy_set(args.output, args.mode, args.namespace)
        print(f"Generated {len(files)} drift policies in {args.output}:")
        for f in files:
            print(f"  {f}")
    else:
        parser.print_help()
