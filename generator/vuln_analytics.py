#!/usr/bin/env python3
"""Analytics functions for vulnerability data."""
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
import json

from vuln_models import (
    ContainerVulnerability,
    VulnEventCorrelation,
    VulnAnalyticsReport,
    Severity,
)
from vuln_correlator import calculate_risk_score


def pareto_analysis(
    correlations: List[VulnEventCorrelation],
    target_coverage: float = 0.8
) -> Tuple[List[Dict[str, Any]], float]:
    """
    Find the minimum set of vulnerabilities that account for target_coverage of correlated events.

    Args:
        correlations: List of vulnerability-event correlations
        target_coverage: Target percentage of events to cover (default 80%)

    Returns:
        Tuple of (list of vulns with event counts, actual coverage percentage)
    """
    vuln_event_counts: Dict[str, Dict[str, Any]] = {}

    for corr in correlations:
        vuln = corr.vulnerability
        key = vuln.cve_id or vuln.vuln_id

        if key not in vuln_event_counts:
            vuln_event_counts[key] = {
                "vuln_id": vuln.vuln_id,
                "cve_id": vuln.cve_id,
                "severity": vuln.severity_string,
                "title": vuln.title or vuln.package_name,
                "event_count": 0,
                "risk_score": vuln.risk_score(),
                "actively_exploited": vuln.actively_exploited,
            }

        vuln_event_counts[key]["event_count"] += len(corr.events)

    sorted_vulns = sorted(
        vuln_event_counts.values(),
        key=lambda x: x["event_count"],
        reverse=True
    )

    total_events = sum(v["event_count"] for v in sorted_vulns)
    if total_events == 0:
        return [], 0.0

    cumulative = 0
    pareto_vulns = []

    for vuln in sorted_vulns:
        cumulative += vuln["event_count"]
        pareto_vulns.append(vuln)

        if cumulative / total_events >= target_coverage:
            break

    actual_coverage = (cumulative / total_events) * 100 if total_events > 0 else 0.0

    return pareto_vulns, actual_coverage


def highest_risk_vulns(
    vulnerabilities: List[ContainerVulnerability],
    correlations: Optional[List[VulnEventCorrelation]] = None,
    top_n: int = 10
) -> List[Dict[str, Any]]:
    """
    Get the highest risk vulnerabilities.

    Args:
        vulnerabilities: List of vulnerabilities
        correlations: Optional list of correlations to factor in event counts
        top_n: Number of top vulnerabilities to return

    Returns:
        List of vulnerability info dicts sorted by risk score
    """
    event_counts: Dict[str, int] = defaultdict(int)
    if correlations:
        for corr in correlations:
            key = corr.vulnerability.vuln_id
            event_counts[key] += len(corr.events)

    vuln_risks = []
    for vuln in vulnerabilities:
        risk = calculate_risk_score(vuln, event_counts.get(vuln.vuln_id, 0))
        vuln_risks.append({
            "vuln_id": vuln.vuln_id,
            "cve_id": vuln.cve_id,
            "severity": vuln.severity_string,
            "cvss_score": vuln.cvss_score,
            "actively_exploited": vuln.actively_exploited,
            "exploitable": vuln.exploitable,
            "risk_score": round(risk, 1),
            "image_name": vuln.image_name,
            "package_name": vuln.package_name,
            "correlated_events": event_counts.get(vuln.vuln_id, 0),
        })

    sorted_vulns = sorted(vuln_risks, key=lambda x: x["risk_score"], reverse=True)
    return sorted_vulns[:top_n]


def generate_report(
    vulnerabilities: List[ContainerVulnerability],
    correlations: List[VulnEventCorrelation],
    containers: Optional[List[Dict[str, Any]]] = None,
) -> VulnAnalyticsReport:
    """
    Generate a comprehensive analytics report.

    Args:
        vulnerabilities: List of vulnerabilities
        correlations: List of correlations
        containers: Optional list of running containers

    Returns:
        VulnAnalyticsReport object
    """
    by_severity: Dict[str, int] = defaultdict(int)
    unique_images: set = set()

    for vuln in vulnerabilities:
        by_severity[vuln.severity_string] += 1
        unique_images.add(vuln.image_id)

    correlated_vuln_ids = {c.vulnerability.vuln_id for c in correlations}

    pareto_vulns, pareto_coverage = pareto_analysis(correlations)
    top_risks = highest_risk_vulns(vulnerabilities, correlations, top_n=10)

    return VulnAnalyticsReport(
        total_vulnerabilities=len(vulnerabilities),
        with_runtime_correlation=len(correlated_vuln_ids),
        unique_images_affected=len(unique_images),
        running_containers=len(containers) if containers else 0,
        by_severity=dict(by_severity),
        pareto_vulns=pareto_vulns,
        pareto_coverage=pareto_coverage,
        highest_risk=top_risks,
    )


def format_report_text(report: VulnAnalyticsReport) -> str:
    """Format analytics report as text for CLI output."""
    lines = []
    lines.append("=" * 80)
    lines.append("Vulnerability Analytics Report")
    lines.append("=" * 80)
    lines.append("")

    lines.append("SUMMARY")
    lines.append(f"  Total Vulnerabilities:     {report.total_vulnerabilities}")
    lines.append(f"  With Runtime Correlation:  {report.with_runtime_correlation}")
    lines.append(f"  Unique Images Affected:    {report.unique_images_affected}")
    lines.append(f"  Running Containers:        {report.running_containers}")
    lines.append("")

    if report.pareto_vulns:
        lines.append(f"PARETO ANALYSIS (Top vulns that fix {report.pareto_coverage:.1f}% of issues)")
        lines.append(f"  Fixing {len(report.pareto_vulns)} vulnerabilities would address {report.pareto_coverage:.1f}% of correlated events:")
        lines.append("")

        for i, vuln in enumerate(report.pareto_vulns[:10], 1):
            cve = vuln.get("cve_id") or vuln.get("vuln_id")
            sev = vuln.get("severity", "MEDIUM")
            title = vuln.get("title", "")[:30]
            events = vuln.get("event_count", 0)
            exploited = " *" if vuln.get("actively_exploited") else ""
            lines.append(f"  {i:2}. {cve:<16} ({sev:<8}) - {title:<30} [{events} events]{exploited}")

        lines.append("")

    if report.highest_risk:
        lines.append("HIGHEST RISK VULNERABILITIES")
        lines.append("  #   CVE              Severity  CVSS   Exploited  Risk Score")
        lines.append("  " + "-" * 60)

        for i, vuln in enumerate(report.highest_risk[:10], 1):
            cve = (vuln.get("cve_id") or vuln.get("vuln_id"))[:16]
            sev = vuln.get("severity", "MEDIUM")[:8]
            cvss = vuln.get("cvss_score")
            cvss_str = f"{cvss:.1f}" if cvss else "N/A"
            exploited = "YES" if vuln.get("actively_exploited") else "NO"
            risk = vuln.get("risk_score", 0)
            lines.append(f"  {i:2}  {cve:<16} {sev:<9} {cvss_str:<6} {exploited:<10} {risk:.1f}")

        lines.append("")

    if report.by_severity:
        lines.append("BY SEVERITY")
        order = ["CRITICAL", "URGENT", "HIGH", "MEDIUM", "LOW"]
        for sev in order:
            if sev in report.by_severity:
                lines.append(f"  {sev}: {report.by_severity[sev]}")
        lines.append("")

    return "\n".join(lines)


def export_data(
    vulnerabilities: List[ContainerVulnerability],
    events: List[Any],
    correlations: List[VulnEventCorrelation],
    report: VulnAnalyticsReport,
    format: str = "json"
) -> str:
    """
    Export all data for external scripting.

    Args:
        vulnerabilities: List of vulnerabilities
        events: List of CDR events
        correlations: List of correlations
        report: Analytics report
        format: Output format ('json' or 'csv')

    Returns:
        Formatted string
    """
    if format == "json":
        data = {
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "cve_id": v.cve_id,
                    "severity": v.severity_string,
                    "cvss_score": v.cvss_score,
                    "image_id": v.image_id,
                    "image_name": v.image_name,
                    "package_name": v.package_name,
                    "package_path": v.package_path,
                    "exploitable": v.exploitable,
                    "actively_exploited": v.actively_exploited,
                    "risk_score": v.risk_score(),
                }
                for v in vulnerabilities
            ],
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "timestamp": e.timestamp,
                    "container_id": e.container_id,
                    "mitre_techniques": e.mitre_techniques,
                    "description": e.description,
                }
                for e in events
            ],
            "correlations": [
                {
                    "vuln_id": c.vulnerability.vuln_id,
                    "cve_id": c.vulnerability.cve_id,
                    "event_count": len(c.events),
                    "confidence": c.confidence,
                    "matched_by": c.matched_by,
                    "combined_risk_score": c.combined_risk_score,
                }
                for c in correlations
            ],
            "analytics": report.to_dict(),
        }
        return json.dumps(data, indent=2)

    elif format == "csv":
        lines = ["vuln_id,cve_id,severity,cvss_score,image_name,package_name,exploitable,actively_exploited,risk_score,correlated_events"]

        event_counts: Dict[str, int] = defaultdict(int)
        for c in correlations:
            event_counts[c.vulnerability.vuln_id] += len(c.events)

        for v in vulnerabilities:
            lines.append(
                f"{v.vuln_id},{v.cve_id or ''},{v.severity_string},{v.cvss_score or ''},"
                f"{v.image_name},{v.package_name},{v.exploitable},{v.actively_exploited},"
                f"{v.risk_score():.1f},{event_counts.get(v.vuln_id, 0)}"
            )

        return "\n".join(lines)

    return ""
