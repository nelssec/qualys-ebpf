#!/usr/bin/env python3
"""Vulnerability correlation engine for matching vulns with runtime events."""
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Any
from collections import defaultdict

from vuln_models import ContainerVulnerability, VulnEventCorrelation
from qualys_cdr_client import CDREvent


@dataclass
class CorrelationConfig:
    """Configuration for correlation engine."""
    container_match_confidence: float = 0.9
    binary_match_confidence: float = 0.95
    mitre_overlap_confidence: float = 0.7
    cve_signature_confidence: float = 1.0
    min_confidence_threshold: float = 0.5


CVE_EXPLOIT_SIGNATURES = {
    "CVE-2024-21626": {
        "process_paths": ["/proc/self/fd"],
        "syscalls": ["sys_setns", "sys_unshare"],
        "mitre": ["T1611"],
    },
    "CVE-2023-44487": {
        "ports": [80, 443, 8080, 8443],
        "mitre": ["T1499"],
    },
    "CVE-2023-38545": {
        "process_names": ["curl"],
        "mitre": ["T1071"],
    },
    "CVE-2024-3094": {
        "process_names": ["sshd"],
        "process_paths": ["/usr/sbin/sshd"],
        "mitre": ["T1059"],
    },
    "CVE-2023-4911": {
        "process_paths": ["/lib/x86_64-linux-gnu/libc.so"],
        "mitre": ["T1068"],
    },
}


class VulnCorrelator:
    """Correlates vulnerabilities with runtime events."""

    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or CorrelationConfig()

    def correlate(
        self,
        vulnerabilities: List[ContainerVulnerability],
        events: List[CDREvent]
    ) -> List[VulnEventCorrelation]:
        """
        Correlate vulnerabilities with runtime events using multiple strategies.

        Args:
            vulnerabilities: List of vulnerabilities from container images
            events: List of CDR runtime events

        Returns:
            List of VulnEventCorrelation objects
        """
        vulns_by_container = self._group_vulns_by_container(vulnerabilities)
        vulns_by_image = self._group_vulns_by_image(vulnerabilities)
        vulns_by_binary = self._group_vulns_by_binary(vulnerabilities)
        vulns_by_technique = self._group_vulns_by_technique(vulnerabilities)
        vulns_by_cve = {v.cve_id: v for v in vulnerabilities if v.cve_id}

        correlations: Dict[str, VulnEventCorrelation] = {}

        for event in events:
            matches = self._find_matches(
                event,
                vulns_by_container,
                vulns_by_image,
                vulns_by_binary,
                vulns_by_technique,
                vulns_by_cve,
            )

            for vuln, confidence, matched_by in matches:
                if confidence < self.config.min_confidence_threshold:
                    continue

                key = f"{vuln.vuln_id}:{vuln.image_id}"
                if key in correlations:
                    correlations[key].events.append(event)
                    correlations[key].confidence = max(
                        correlations[key].confidence, confidence
                    )
                else:
                    correlations[key] = VulnEventCorrelation(
                        vulnerability=vuln,
                        events=[event],
                        confidence=confidence,
                        matched_by=matched_by,
                    )

        return list(correlations.values())

    def _find_matches(
        self,
        event: CDREvent,
        vulns_by_container: Dict[str, List[ContainerVulnerability]],
        vulns_by_image: Dict[str, List[ContainerVulnerability]],
        vulns_by_binary: Dict[str, List[ContainerVulnerability]],
        vulns_by_technique: Dict[str, List[ContainerVulnerability]],
        vulns_by_cve: Dict[str, ContainerVulnerability],
    ) -> List[tuple]:
        """Find all vulnerability matches for an event."""
        matches = []

        if event.container_id and event.container_id in vulns_by_container:
            for vuln in vulns_by_container[event.container_id]:
                matches.append((
                    vuln,
                    self.config.container_match_confidence,
                    "container_match"
                ))

        process_path = event.raw_data.get("processPath", "")
        if process_path and process_path in vulns_by_binary:
            for vuln in vulns_by_binary[process_path]:
                matches.append((
                    vuln,
                    self.config.binary_match_confidence,
                    "process_binary"
                ))

        for technique in event.mitre_techniques:
            if technique in vulns_by_technique:
                for vuln in vulns_by_technique[technique]:
                    matches.append((
                        vuln,
                        self.config.mitre_overlap_confidence,
                        "mitre_overlap"
                    ))

        cve_matches = self._match_cve_signatures(event, vulns_by_cve)
        matches.extend(cve_matches)

        seen = set()
        unique_matches = []
        for vuln, conf, method in matches:
            key = f"{vuln.vuln_id}:{vuln.image_id}"
            if key not in seen:
                seen.add(key)
                unique_matches.append((vuln, conf, method))
            else:
                for i, (v, c, m) in enumerate(unique_matches):
                    if f"{v.vuln_id}:{v.image_id}" == key and conf > c:
                        unique_matches[i] = (vuln, conf, method)

        return unique_matches

    def _match_cve_signatures(
        self,
        event: CDREvent,
        vulns_by_cve: Dict[str, ContainerVulnerability]
    ) -> List[tuple]:
        """Match events against known CVE exploit signatures."""
        matches = []

        for cve_id, signature in CVE_EXPLOIT_SIGNATURES.items():
            if cve_id not in vulns_by_cve:
                continue

            vuln = vulns_by_cve[cve_id]
            matched = False

            process_path = event.raw_data.get("processPath", "")
            process_name = event.raw_data.get("processName", "")

            if "process_paths" in signature:
                for path in signature["process_paths"]:
                    if path in process_path:
                        matched = True
                        break

            if "process_names" in signature:
                for name in signature["process_names"]:
                    if name in process_name:
                        matched = True
                        break

            if "mitre" in signature:
                for tech in signature["mitre"]:
                    if tech in event.mitre_techniques:
                        matched = True
                        break

            if "syscalls" in signature:
                syscall = event.raw_data.get("syscall", "")
                if syscall in signature["syscalls"]:
                    matched = True

            if matched:
                matches.append((
                    vuln,
                    self.config.cve_signature_confidence,
                    "cve_signature"
                ))

        return matches

    def _group_vulns_by_container(
        self, vulns: List[ContainerVulnerability]
    ) -> Dict[str, List[ContainerVulnerability]]:
        grouped: Dict[str, List[ContainerVulnerability]] = defaultdict(list)
        for vuln in vulns:
            for container_id in vuln.container_ids:
                grouped[container_id].append(vuln)
        return dict(grouped)

    def _group_vulns_by_image(
        self, vulns: List[ContainerVulnerability]
    ) -> Dict[str, List[ContainerVulnerability]]:
        grouped: Dict[str, List[ContainerVulnerability]] = defaultdict(list)
        for vuln in vulns:
            grouped[vuln.image_id].append(vuln)
        return dict(grouped)

    def _group_vulns_by_binary(
        self, vulns: List[ContainerVulnerability]
    ) -> Dict[str, List[ContainerVulnerability]]:
        grouped: Dict[str, List[ContainerVulnerability]] = defaultdict(list)
        for vuln in vulns:
            if vuln.package_path:
                grouped[vuln.package_path].append(vuln)
        return dict(grouped)

    def _group_vulns_by_technique(
        self, vulns: List[ContainerVulnerability]
    ) -> Dict[str, List[ContainerVulnerability]]:
        grouped: Dict[str, List[ContainerVulnerability]] = defaultdict(list)
        for vuln in vulns:
            for technique in vuln.mitre_techniques:
                grouped[technique].append(vuln)
        return dict(grouped)


def calculate_risk_score(
    vuln: ContainerVulnerability,
    correlated_events: int = 0
) -> float:
    """
    Calculate combined risk score for a vulnerability.

    Formula: risk = (severity/5) * (cvss/10) * exploitability_multiplier * exposure_multiplier
    """
    severity_factor = vuln.severity / 5.0
    cvss_factor = (vuln.cvss_score or 5.0) / 10.0

    if vuln.actively_exploited:
        exploit_multiplier = 2.0
    elif vuln.exploitable:
        exploit_multiplier = 1.5
    else:
        exploit_multiplier = 1.0

    exposure_multiplier = 1 + (0.1 * correlated_events)

    return min(severity_factor * cvss_factor * exploit_multiplier * exposure_multiplier * 100, 100.0)
