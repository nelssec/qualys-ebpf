#!/usr/bin/env python3
"""Qualys CDR (Cloud Detection and Response) API client."""
import os
import requests
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json


@dataclass
class QualysCDRConfig:
    """Qualys CDR API configuration."""
    gateway_url: str
    username: str
    password: str
    cdr_base: str = "/cdr-api/rest/v1"
    cs_base: str = "/csapi/v1.3"

    @classmethod
    def from_env(cls) -> "QualysCDRConfig":
        """Load configuration from environment variables."""
        return cls(
            gateway_url=os.environ.get("QUALYS_GATEWAY_URL", "gateway.qg1.apps.qualys.ca"),
            username=os.environ.get("QUALYS_USERNAME", ""),
            password=os.environ.get("QUALYS_PASSWORD", ""),
        )

    @property
    def auth_url(self) -> str:
        return f"https://{self.gateway_url}/auth"

    @property
    def cdr_url(self) -> str:
        return f"https://{self.gateway_url}{self.cdr_base}"

    @property
    def cs_url(self) -> str:
        return f"https://{self.gateway_url}{self.cs_base}"


@dataclass
class CDREvent:
    """CDR detection event."""
    event_id: str
    event_type: str
    severity: str
    timestamp: str
    resource_type: str
    resource_id: str
    description: str
    mitre_techniques: List[str] = field(default_factory=list)
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    cluster_name: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContainerRuntimeEvent:
    """Container runtime security event."""
    event_id: str
    event_type: str  # process, file, network, syscall
    action: str
    timestamp: str
    container_id: str
    container_name: str
    image_name: str
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    file_path: Optional[str] = None
    syscall: Optional[str] = None
    severity: str = "medium"
    raw_data: Dict[str, Any] = field(default_factory=dict)


class QualysCDRClient:
    """Client for Qualys CDR and Container Security APIs."""

    def __init__(self, config: QualysCDRConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "Python QualysCDRClient",
        })
        self._token = None

    def _get_auth_token(self) -> str:
        """Get JWT auth token from Qualys gateway."""
        if self._token:
            return self._token

        # URL encode the password (handle special chars like @)
        import urllib.parse
        password_encoded = urllib.parse.quote(self.config.password, safe='')

        response = requests.post(
            self.config.auth_url,
            data=f"username={self.config.username}&password={password_encoded}&token=true",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        self._token = response.text
        return self._token

    def _api_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated API request with Bearer token."""
        try:
            token = self._get_auth_token()
            headers = kwargs.pop("headers", {})
            headers["Authorization"] = f"Bearer {token}"

            response = self.session.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.RequestException as e:
            print(f"API request failed: {e}")
            return {}

    def get_cdr_detections(self,
                          hours: int = 24,
                          severity: Optional[str] = None,
                          resource_type: Optional[str] = None,
                          limit: int = 100) -> List[CDREvent]:
        """Fetch CDR detection events (findings)."""
        url = f"{self.config.cdr_url}/findings"

        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        params = {
            "startAt": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "endAt": end_time.strftime("%Y-%m-%dT%H:%M:%S.999Z"),
            "limit": limit,
        }

        if resource_type:
            params["resourceType"] = resource_type
        if severity:
            # Map text severity to numeric if needed
            severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if severity.upper() in severity_map:
                params["severity"] = severity_map[severity.upper()]
            else:
                params["severity"] = severity

        data = self._api_request("GET", url, params=params)

        events = []
        for item in data.get("content", []):
            # Extract MITRE info if available
            mitre_info = item.get("mitreRulesInfo") or {}
            mitre_techniques = []
            if isinstance(mitre_info, dict):
                mitre_techniques = list(mitre_info.keys())
            elif isinstance(mitre_info, list):
                mitre_techniques = [m.get("technique", "") for m in mitre_info if m.get("technique")]

            events.append(CDREvent(
                event_id=item.get("uuid", ""),
                event_type=item.get("threatCategory", ""),
                severity=self._map_severity(item.get("severity", 2)),
                timestamp=item.get("timestamp", ""),
                resource_type=item.get("resourceType", ""),
                resource_id=item.get("resourceId", ""),
                description=item.get("eventMessage", ""),
                mitre_techniques=mitre_techniques,
                container_id=item.get("containerName"),  # Note: containerName used as ID
                container_name=item.get("containerName"),
                pod_name=item.get("pod"),
                namespace=None,  # Extract from podLabels if needed
                cluster_name=item.get("deploymentName"),
                raw_data=item,
            ))

        return events

    def _map_severity(self, numeric_severity: int) -> str:
        """Map numeric severity to string."""
        severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "CRITICAL"}
        return severity_map.get(numeric_severity, "MEDIUM")

    def get_cdr_event_details(self, event_id: str) -> Optional[CDREvent]:
        """Get detailed information about a specific CDR event."""
        url = f"{self.config.cdr_url}/cdr/detections/{event_id}"
        data = self._api_request("GET", url)

        if not data:
            return None

        return CDREvent(
            event_id=data.get("id", ""),
            event_type=data.get("detectionType", ""),
            severity=data.get("severity", "MEDIUM"),
            timestamp=data.get("detectedOn", ""),
            resource_type=data.get("resourceType", ""),
            resource_id=data.get("resourceId", ""),
            description=data.get("description", ""),
            mitre_techniques=data.get("mitreTechniques", []),
            container_id=data.get("containerId"),
            container_name=data.get("containerName"),
            pod_name=data.get("podName"),
            namespace=data.get("namespace"),
            cluster_name=data.get("clusterName"),
            raw_data=data,
        )

    def get_runtime_events(self,
                          container_id: Optional[str] = None,
                          event_type: Optional[str] = None,
                          hours: int = 24) -> List[ContainerRuntimeEvent]:
        """
        Fetch container runtime events from CRS.

        Args:
            container_id: Filter by specific container
            event_type: Filter by event type (process, file, network, syscall)
            hours: Look back period

        Returns:
            List of ContainerRuntimeEvent objects
        """
        url = f"{self.config.cs_url}/crs/events"

        params = {
            "pageSize": 100,
        }

        if container_id:
            params["containerId"] = container_id
        if event_type:
            params["eventType"] = event_type

        data = self._api_request("GET", url, params=params)

        events = []
        for item in data.get("events", []):
            events.append(ContainerRuntimeEvent(
                event_id=item.get("id", ""),
                event_type=item.get("eventType", ""),
                action=item.get("action", ""),
                timestamp=item.get("timestamp", ""),
                container_id=item.get("containerId", ""),
                container_name=item.get("containerName", ""),
                image_name=item.get("imageName", ""),
                process_name=item.get("processName"),
                process_path=item.get("processPath"),
                file_path=item.get("filePath"),
                syscall=item.get("syscall"),
                severity=item.get("severity", "medium"),
                raw_data=item,
            ))

        return events

    def get_container_baseline(self, container_id: str) -> Dict[str, Any]:
        """
        Get behavioral baseline for a container.

        Returns learned normal behavior including:
        - Expected processes
        - Normal file access patterns
        - Expected network connections
        """
        url = f"{self.config.cs_url}/crs/baselines/{container_id}"
        return self._api_request("GET", url)

    def get_runtime_policies(self) -> List[Dict[str, Any]]:
        """Get currently deployed runtime policies."""
        url = f"{self.config.cs_url}/crs/policies"
        data = self._api_request("GET", url)
        return data.get("policies", [])

    def create_runtime_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new runtime security policy in Qualys.

        Args:
            policy: Policy definition dict

        Returns:
            Created policy details
        """
        url = f"{self.config.cs_url}/crs/policies"
        return self._api_request("POST", url, json=policy)

    def generate_policy_from_detections(self,
                                        events: List[CDREvent],
                                        action: str = "Post") -> List[Dict[str, Any]]:
        """Generate TracingPolicy specs from CDR detection events."""
        policies = []

        # Group events by MITRE technique
        by_technique = {}
        for event in events:
            for technique in event.mitre_techniques:
                if technique not in by_technique:
                    by_technique[technique] = []
                by_technique[technique].append(event)

        for technique, tech_events in by_technique.items():
            policy = self._create_policy_for_technique(technique, tech_events, action)
            if policy:
                policies.append(policy)

        # Also group by threat category if no MITRE techniques
        by_category = {}
        for event in events:
            if not event.mitre_techniques and event.event_type:
                category = event.event_type
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(event)

        for category, cat_events in by_category.items():
            policy = self._create_policy_for_category(category, cat_events, action)
            if policy:
                policies.append(policy)

        return policies

    def _create_policy_for_category(self,
                                    category: str,
                                    events: List[CDREvent],
                                    action: str) -> Optional[Dict[str, Any]]:
        """Create a policy based on threat category."""

        # Map threat categories to policy templates
        category_map = {
            "Networking_Suspicious_Communication": self._policy_suspicious_network,
            "Networking_C2_Communication": self._policy_c2_communication,
            "Container_Escape": self._policy_container_escape,
            "Privilege_Escalation": self._policy_privilege_escalation,
            "Credential_Access": self._policy_credential_access,
            "Crypto_Mining": self._policy_crypto_mining,
            # New categories from US2 CDR events
            "Cloud_Credentials_Accessed_By_Network_Utility": self._policy_cloud_credential_access,
            "Network_Scanning_Utility": self._policy_network_scanning,
        }

        # Find matching template
        for cat_pattern, policy_func in category_map.items():
            if cat_pattern.lower() in category.lower():
                return policy_func(events, action)

        # Default: create a generic network policy for suspicious communication
        if "network" in category.lower() or "communication" in category.lower():
            return self._policy_suspicious_network(events, action)

        return None

    def _policy_suspicious_network(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for suspicious network communication."""
        # Extract suspicious IPs from events
        suspicious_ips = set()
        for event in events:
            if event.raw_data.get("triggeredResource"):
                suspicious_ips.add(event.raw_data["triggeredResource"])

        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-suspicious-network-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "threat.qualys.com/category": "suspicious-communication",
                    "policy.qualys.com/priority": "high",
                },
                "annotations": {
                    "suspicious-ips": ",".join(list(suspicious_ips)[:10]),
                    "event-count": str(len(events)),
                },
            },
            "spec": {
                "kprobes": [{
                    "call": "sys_connect",
                    "syscall": True,
                    "args": [{"index": 1, "type": "sockaddr"}],
                    "selectors": [{
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }

    def _policy_crypto_mining(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for crypto mining detection."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-crypto-mining-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1496",
                    "policy.qualys.com/priority": "high",
                },
            },
            "spec": {
                "kprobes": [
                    {
                        "call": "sys_connect",
                        "syscall": True,
                        "args": [{"index": 1, "type": "sockaddr"}],
                        "selectors": [{
                            "matchArgs": [{
                                "index": 1,
                                "operator": "DPort",
                                "values": ["3333", "4444", "5555", "14433", "14444"],
                            }],
                            "matchActions": [{"action": action}],
                        }],
                    },
                ],
            },
        }

    def _create_policy_for_technique(self,
                                     technique: str,
                                     events: List[CDREvent],
                                     action: str) -> Optional[Dict[str, Any]]:
        """Create a policy for a specific MITRE technique based on observed events."""

        # Map MITRE techniques to policy templates
        technique_map = {
            "T1059": self._policy_command_execution,
            "T1059.004": self._policy_shell_execution,
            "T1611": self._policy_container_escape,
            "T1548": self._policy_privilege_escalation,
            "T1552": self._policy_credential_access,
            "T1046": self._policy_network_scanning,
            "T1071": self._policy_c2_communication,
        }

        # Find matching template
        for tech_prefix, policy_func in technique_map.items():
            if technique.startswith(tech_prefix):
                return policy_func(events, action)

        return None

    def _policy_command_execution(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for command/script execution."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-generated-exec-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1059",
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
                            "values": ["/sh", "/bash", "/python", "/perl"],
                        }],
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }

    def _policy_shell_execution(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for Unix shell execution detection."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-generated-shell-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1059.004",
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
                            "values": ["/sh", "/bash", "/dash", "/zsh", "/ash"],
                        }],
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }

    def _policy_container_escape(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for container escape attempts."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-generated-escape-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1611",
                    "priority": "critical",
                },
            },
            "spec": {
                "kprobes": [
                    {
                        "call": "sys_unshare",
                        "syscall": True,
                        "args": [{"index": 0, "type": "int"}],
                        "selectors": [{
                            "matchNamespaceChanges": [{
                                "operator": "In",
                                "values": ["User", "Mnt", "Pid"],
                            }],
                            "matchActions": [{"action": action}],
                        }],
                    },
                    {
                        "call": "sys_setns",
                        "syscall": True,
                        "args": [
                            {"index": 0, "type": "int"},
                            {"index": 1, "type": "int"},
                        ],
                        "selectors": [{"matchActions": [{"action": action}]}],
                    },
                ],
            },
        }

    def _policy_privilege_escalation(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for privilege escalation attempts."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-generated-privesc-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1548",
                    "priority": "high",
                },
            },
            "spec": {
                "kprobes": [{
                    "call": "sys_setuid",
                    "syscall": True,
                    "args": [{"index": 0, "type": "int"}],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 0,
                            "operator": "Equal",
                            "values": ["0"],
                        }],
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }

    def _policy_credential_access(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for credential file access."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-generated-creds-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1552",
                },
            },
            "spec": {
                "kprobes": [{
                    "call": "sys_openat",
                    "syscall": True,
                    "args": [{"index": 1, "type": "string"}],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 1,
                            "operator": "Postfix",
                            "values": [
                                "/etc/shadow", "/etc/passwd",
                                "/.ssh/id_rsa", "/.aws/credentials",
                            ],
                        }],
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }

    def _policy_network_scanning(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for network scanning detection."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-generated-scan-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1046",
                },
            },
            "spec": {
                "kprobes": [{
                    "call": "sys_socket",
                    "syscall": True,
                    "args": [
                        {"index": 0, "type": "int"},
                        {"index": 1, "type": "int"},
                    ],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 1,
                            "operator": "Equal",
                            "values": ["3"],  # SOCK_RAW
                        }],
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }

    def _policy_c2_communication(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for C2 communication detection."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-generated-c2-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1071",
                },
            },
            "spec": {
                "kprobes": [{
                    "call": "sys_connect",
                    "syscall": True,
                    "args": [{"index": 1, "type": "sockaddr"}],
                    "selectors": [{
                        "matchArgs": [{
                            "index": 1,
                            "operator": "DPort",
                            "values": ["4444", "5555", "6666", "8443"],
                        }],
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }

    def _policy_cloud_credential_access(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for cloud credential/IMDS access via network utilities.

        Detects pattern: curl/wget accessing 169.254.169.254 (AWS/GCP/Azure metadata)
        """
        # Extract process names from events
        processes = set()
        for event in events:
            proc = event.raw_data.get("processName", "")
            if proc:
                processes.add(proc)

        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-block-cloud-creds-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1552.005",
                    "mitre.attack/tactic": "credential-access",
                    "policy.qualys.com/priority": "critical",
                },
                "annotations": {
                    "description": "Block network utilities accessing cloud metadata endpoints",
                    "detected-processes": ",".join(list(processes)[:5]),
                    "event-count": str(len(events)),
                },
            },
            "spec": {
                "kprobes": [
                    {
                        "call": "sys_connect",
                        "syscall": True,
                        "args": [
                            {"index": 0, "type": "int"},
                            {"index": 1, "type": "sockaddr"},
                        ],
                        "selectors": [{
                            "matchArgs": [{
                                "index": 1,
                                "operator": "SAddr",
                                "values": ["169.254.169.254"],
                            }],
                            "matchBinaries": [{
                                "operator": "In",
                                "values": [
                                    "/usr/bin/curl",
                                    "/usr/bin/wget",
                                    "/usr/bin/fetch",
                                    "/usr/bin/httpie",
                                ],
                            }],
                            "matchActions": [{"action": action}],
                        }],
                    },
                    {
                        "call": "sys_execve",
                        "syscall": True,
                        "args": [
                            {"index": 0, "type": "string"},
                            {"index": 1, "type": "string"},
                        ],
                        "selectors": [{
                            "matchArgs": [
                                {
                                    "index": 0,
                                    "operator": "Postfix",
                                    "values": ["/curl", "/wget"],
                                },
                                {
                                    "index": 1,
                                    "operator": "Contains",
                                    "values": [
                                        "169.254.169.254",
                                        "metadata.google.internal",
                                    ],
                                },
                            ],
                            "matchActions": [{"action": action}],
                        }],
                    },
                ],
            },
        }

    def _policy_network_scanning(self, events: List[CDREvent], action: str) -> Dict:
        """Generate policy for network scanning utility detection.

        Detects pattern: nmap, masscan, netcat used in containers
        """
        # Extract scanning tools from events
        tools = set()
        for event in events:
            proc = event.raw_data.get("processName", "")
            if proc:
                tools.add(proc)

        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": f"cdr-block-network-scan-{datetime.utcnow().strftime('%Y%m%d')}",
                "labels": {
                    "generated-by": "qualys-cdr",
                    "mitre.attack/technique": "T1046",
                    "mitre.attack/tactic": "discovery",
                    "policy.qualys.com/priority": "high",
                },
                "annotations": {
                    "description": "Block network scanning and enumeration tools",
                    "detected-tools": ",".join(list(tools)[:5]),
                    "event-count": str(len(events)),
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
                                "operator": "Postfix",
                                "values": [
                                    "/nmap", "/masscan", "/zmap", "/rustscan",
                                    "/netcat", "/nc", "/ncat", "/socat",
                                    "/fping", "/hping", "/hping3",
                                ],
                            }],
                            "matchActions": [{"action": action}],
                        }],
                    },
                    {
                        "call": "sys_socket",
                        "syscall": True,
                        "args": [
                            {"index": 0, "type": "int"},
                            {"index": 1, "type": "int"},
                        ],
                        "selectors": [{
                            "matchArgs": [{
                                "index": 1,
                                "operator": "Equal",
                                "values": ["3"],  # SOCK_RAW
                            }],
                            "matchActions": [{"action": action}],
                        }],
                    },
                ],
            },
        }


def main():
    """CLI for Qualys CDR client."""
    import argparse
    import yaml

    parser = argparse.ArgumentParser(description="Qualys CDR Client")
    parser.add_argument("--platform", default="qualysguard.qg2.apps.qualys.com",
                       help="Qualys platform URL")
    parser.add_argument("--hours", type=int, default=24,
                       help="Look back period in hours")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                       help="Filter by severity")
    parser.add_argument("--output", "-o", default="./cdr-generated-policies",
                       help="Output directory")
    parser.add_argument("--action", choices=["Post", "Sigkill"], default="Post",
                       help="Default action for generated policies")

    args = parser.parse_args()

    config = QualysCDRConfig.from_env()
    if args.platform:
        config.platform_url = args.platform

    if not config.username or not config.password:
        print("Error: Set QUALYS_USERNAME and QUALYS_PASSWORD environment variables")
        print("")
        print("Qualys Platform URLs:")
        print("  US Platform 2: qualysguard.qg2.apps.qualys.com")
        print("  Canada: qualysguard.qg1.apps.qualys.ca")
        print("  EU: qualysguard.qg2.apps.qualys.eu")
        print("  India: qualysguard.qg1.apps.qualys.in")
        return

    client = QualysCDRClient(config)

    print(f"Fetching CDR events from last {args.hours} hours...")
    events = client.get_cdr_detections(
        hours=args.hours,
        severity=args.severity,
        resource_type="container",
    )

    print(f"Found {len(events)} container detection events")

    if events:
        print("\nGenerating policies from detections...")
        policies = client.generate_policy_from_detections(events, args.action)

        os.makedirs(args.output, exist_ok=True)
        for policy in policies:
            name = policy["metadata"]["name"]
            filepath = os.path.join(args.output, f"{name}.yaml")
            with open(filepath, "w") as f:
                yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
            print(f"  Generated: {filepath}")

        print(f"\nGenerated {len(policies)} policies in {args.output}")
    else:
        print("No events found. Ensure CDR is configured and generating detections.")


if __name__ == "__main__":
    main()
