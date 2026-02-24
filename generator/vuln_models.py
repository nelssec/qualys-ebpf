#!/usr/bin/env python3
"""Data models for vulnerability tracking and correlation."""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    URGENT = 5

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "urgent": cls.URGENT,
        }
        return mapping.get(s.lower(), cls.MEDIUM)

    def to_string(self) -> str:
        return self.name


@dataclass
class ContainerVulnerability:
    """Vulnerability found in a container image."""
    vuln_id: str
    cve_id: Optional[str]
    severity: int
    cvss_score: Optional[float]
    image_id: str
    image_name: str
    container_ids: List[str]
    package_name: str
    package_path: str
    mitre_techniques: List[str] = field(default_factory=list)
    exploitable: bool = False
    actively_exploited: bool = False
    title: Optional[str] = None
    description: Optional[str] = None
    fix_version: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_string(self) -> str:
        return Severity(self.severity).to_string()

    @property
    def is_critical(self) -> bool:
        return self.severity >= Severity.CRITICAL

    def risk_score(self) -> float:
        base = (self.severity / 5.0) * ((self.cvss_score or 5.0) / 10.0)
        if self.actively_exploited:
            base *= 2.0
        elif self.exploitable:
            base *= 1.5
        return min(base * 100, 100.0)


@dataclass
class VulnEventCorrelation:
    """Correlation between a vulnerability and runtime events."""
    vulnerability: ContainerVulnerability
    events: List[Any]
    confidence: float
    matched_by: str
    combined_risk_score: float = 0.0

    def __post_init__(self):
        if self.combined_risk_score == 0.0:
            self.combined_risk_score = self._calculate_combined_risk()

    def _calculate_combined_risk(self) -> float:
        vuln_risk = self.vulnerability.risk_score()
        exposure_multiplier = 1 + (0.1 * len(self.events))
        return min(vuln_risk * exposure_multiplier * self.confidence, 100.0)


@dataclass
class VulnAnalyticsReport:
    """Analytics report for vulnerabilities."""
    total_vulnerabilities: int = 0
    with_runtime_correlation: int = 0
    unique_images_affected: int = 0
    running_containers: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    pareto_vulns: List[Dict[str, Any]] = field(default_factory=list)
    pareto_coverage: float = 0.0
    highest_risk: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_vulnerabilities": self.total_vulnerabilities,
                "with_runtime_correlation": self.with_runtime_correlation,
                "unique_images_affected": self.unique_images_affected,
                "running_containers": self.running_containers,
            },
            "by_severity": self.by_severity,
            "pareto": {
                "vulns_for_80_percent": [v.get("cve_id") or v.get("vuln_id") for v in self.pareto_vulns],
                "coverage": self.pareto_coverage,
                "details": self.pareto_vulns,
            },
            "highest_risk": self.highest_risk,
        }
