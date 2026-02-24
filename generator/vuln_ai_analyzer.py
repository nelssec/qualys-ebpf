#!/usr/bin/env python3
"""AI-powered vulnerability analysis using Anthropic Claude."""
import os
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from vuln_models import ContainerVulnerability, VulnEventCorrelation
from qualys_cdr_client import CDREvent


class AnalysisType(Enum):
    EXPLAIN_CVE = "explain_cve"
    VALIDATE_EXPLOIT = "validate_exploit"
    SUGGEST_POLICY = "suggest_policy"
    RISK_ASSESSMENT = "risk_assessment"
    TRIAGE_EVENTS = "triage_events"


@dataclass
class AIAnalysisResult:
    """Result from AI analysis."""
    analysis_type: str
    input_summary: str
    analysis: str
    confidence: float
    recommendations: List[str] = field(default_factory=list)
    suggested_policy: Optional[Dict[str, Any]] = None
    risk_level: Optional[str] = None
    raw_response: str = ""


SYSTEM_PROMPT = """You are a security expert specializing in container security, vulnerability analysis, and eBPF-based runtime protection. You help security teams understand vulnerabilities, validate potential exploits, and create effective detection/prevention policies.

Your expertise includes:
- CVE analysis and exploit techniques
- MITRE ATT&CK framework mapping
- Kubernetes and container security
- eBPF/Tetragon TracingPolicy creation
- Runtime threat detection

When analyzing vulnerabilities:
1. Explain the technical details clearly
2. Describe how the vulnerability could be exploited in containers
3. Identify what syscalls, file accesses, or network activity would indicate exploitation
4. Suggest specific TracingPolicy rules for detection/prevention

When validating events:
1. Assess if the event pattern matches known exploit behavior
2. Consider false positive likelihood
3. Provide confidence level (0-1) for exploit match

Always respond in JSON format with the structure specified in the user prompt."""


class VulnAIAnalyzer:
    """AI-powered vulnerability analysis using Claude."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable required")

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = model

    def _call_claude(self, user_prompt: str, max_tokens: int = 4096) -> str:
        """Make a call to Claude API."""
        message = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}]
        )
        return message.content[0].text

    def explain_cve(self, cve_id: str, context: Optional[Dict[str, Any]] = None) -> AIAnalysisResult:
        """Get detailed explanation of a CVE and how it might be exploited in containers."""
        context_str = ""
        if context:
            context_str = f"\n\nAdditional context:\n{json.dumps(context, indent=2)}"

        prompt = f"""Analyze the vulnerability {cve_id} for container security purposes.{context_str}

Respond in JSON format:
{{
    "cve_id": "{cve_id}",
    "title": "Brief title",
    "severity_assessment": "CRITICAL|HIGH|MEDIUM|LOW",
    "technical_description": "Detailed technical explanation",
    "container_impact": "How this affects containerized workloads",
    "exploit_indicators": {{
        "syscalls": ["list of syscalls that might indicate exploitation"],
        "file_accesses": ["files that might be accessed"],
        "network_activity": ["network patterns to watch for"],
        "process_behavior": ["suspicious process patterns"]
    }},
    "mitre_techniques": ["T1234", "T5678"],
    "detection_strategy": "How to detect exploitation attempts",
    "prevention_strategy": "How to prevent exploitation",
    "confidence": 0.95
}}"""

        response = self._call_claude(prompt)

        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            data = {"analysis": response, "confidence": 0.5}

        return AIAnalysisResult(
            analysis_type=AnalysisType.EXPLAIN_CVE.value,
            input_summary=f"CVE: {cve_id}",
            analysis=data.get("technical_description", response),
            confidence=data.get("confidence", 0.8),
            recommendations=[
                data.get("detection_strategy", ""),
                data.get("prevention_strategy", ""),
            ],
            risk_level=data.get("severity_assessment"),
            raw_response=response,
        )

    def validate_exploit(
        self,
        vulnerability: ContainerVulnerability,
        events: List[CDREvent]
    ) -> AIAnalysisResult:
        """Validate if events indicate exploitation of a specific vulnerability."""
        vuln_data = {
            "cve_id": vulnerability.cve_id,
            "vuln_id": vulnerability.vuln_id,
            "severity": vulnerability.severity_string,
            "package": vulnerability.package_name,
            "package_path": vulnerability.package_path,
            "mitre_techniques": vulnerability.mitre_techniques,
        }

        events_data = [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "description": e.description,
                "mitre_techniques": e.mitre_techniques,
                "container": e.container_name,
                "timestamp": e.timestamp,
                "raw_data_sample": {k: v for k, v in list(e.raw_data.items())[:10]},
            }
            for e in events[:10]
        ]

        prompt = f"""Analyze if these runtime events indicate exploitation of the given vulnerability.

Vulnerability:
{json.dumps(vuln_data, indent=2)}

Runtime Events:
{json.dumps(events_data, indent=2)}

Assess:
1. Do the events match expected exploit behavior for this vulnerability?
2. What is the confidence level that this is an actual exploit vs. benign activity?
3. What additional indicators should we look for?

Respond in JSON format:
{{
    "is_likely_exploit": true|false,
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation of why this does or doesn't look like exploitation",
    "matching_indicators": ["list of specific indicators that matched"],
    "missing_indicators": ["expected indicators that were not observed"],
    "false_positive_likelihood": "HIGH|MEDIUM|LOW",
    "recommended_action": "BLOCK|ALERT|INVESTIGATE|IGNORE",
    "additional_monitoring": ["what else to watch for"]
}}"""

        response = self._call_claude(prompt)

        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            data = {"reasoning": response, "confidence": 0.5, "is_likely_exploit": False}

        risk_map = {
            "BLOCK": "CRITICAL",
            "ALERT": "HIGH",
            "INVESTIGATE": "MEDIUM",
            "IGNORE": "LOW",
        }

        return AIAnalysisResult(
            analysis_type=AnalysisType.VALIDATE_EXPLOIT.value,
            input_summary=f"Vuln: {vulnerability.cve_id or vulnerability.vuln_id}, Events: {len(events)}",
            analysis=data.get("reasoning", response),
            confidence=data.get("confidence", 0.5),
            recommendations=[
                data.get("recommended_action", "INVESTIGATE"),
            ] + data.get("additional_monitoring", []),
            risk_level=risk_map.get(data.get("recommended_action", "INVESTIGATE"), "MEDIUM"),
            raw_response=response,
        )

    def suggest_policy(
        self,
        vulnerability: ContainerVulnerability,
        action: str = "Post"
    ) -> AIAnalysisResult:
        """Generate a TracingPolicy tailored to detect/prevent exploitation of a specific CVE."""
        vuln_data = {
            "cve_id": vulnerability.cve_id,
            "vuln_id": vulnerability.vuln_id,
            "severity": vulnerability.severity_string,
            "cvss_score": vulnerability.cvss_score,
            "package": vulnerability.package_name,
            "package_path": vulnerability.package_path,
            "mitre_techniques": vulnerability.mitre_techniques,
            "description": vulnerability.description,
        }

        prompt = f"""Generate a Cilium/Tetragon TracingPolicy to detect or prevent exploitation of this vulnerability.

Vulnerability:
{json.dumps(vuln_data, indent=2)}

Requested action: {action} (Post = audit/alert, Sigkill = block/kill)

Create a TracingPolicy that:
1. Monitors syscalls, file accesses, or network activity specific to this CVE's exploit pattern
2. Uses appropriate selectors (matchBinaries, matchArgs, etc.)
3. Minimizes false positives while catching exploit attempts

Respond in JSON format:
{{
    "policy_name": "cve-{vulnerability.cve_id or vulnerability.vuln_id}-detection",
    "description": "What this policy detects",
    "tracing_policy": {{
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {{...}},
        "spec": {{...}}
    }},
    "detection_logic": "Explanation of what the policy monitors and why",
    "false_positive_notes": "Potential false positives and how to tune",
    "confidence": 0.0-1.0
}}"""

        response = self._call_claude(prompt)

        try:
            data = json.loads(response)
            policy = data.get("tracing_policy", {})
        except json.JSONDecodeError:
            data = {"detection_logic": response, "confidence": 0.5}
            policy = None

        return AIAnalysisResult(
            analysis_type=AnalysisType.SUGGEST_POLICY.value,
            input_summary=f"Policy for {vulnerability.cve_id or vulnerability.vuln_id}",
            analysis=data.get("detection_logic", response),
            confidence=data.get("confidence", 0.7),
            recommendations=[data.get("false_positive_notes", "")],
            suggested_policy=policy,
            raw_response=response,
        )

    def assess_risk(
        self,
        vulnerabilities: List[ContainerVulnerability],
        correlations: List[VulnEventCorrelation]
    ) -> AIAnalysisResult:
        """Get AI-powered risk assessment for a set of vulnerabilities and correlations."""
        vulns_summary = [
            {
                "cve_id": v.cve_id,
                "severity": v.severity_string,
                "cvss": v.cvss_score,
                "package": v.package_name,
                "exploitable": v.exploitable,
                "actively_exploited": v.actively_exploited,
                "image": v.image_name,
            }
            for v in vulnerabilities[:20]
        ]

        corr_summary = [
            {
                "cve_id": c.vulnerability.cve_id,
                "event_count": len(c.events),
                "confidence": c.confidence,
                "matched_by": c.matched_by,
            }
            for c in correlations[:20]
        ]

        prompt = f"""Perform a risk assessment for this container environment based on vulnerabilities and runtime correlations.

Vulnerabilities ({len(vulnerabilities)} total, showing top 20):
{json.dumps(vulns_summary, indent=2)}

Runtime Correlations ({len(correlations)} total, showing top 20):
{json.dumps(corr_summary, indent=2)}

Provide:
1. Overall risk assessment
2. Most critical vulnerabilities requiring immediate attention
3. Prioritized remediation recommendations
4. Security posture improvement suggestions

Respond in JSON format:
{{
    "overall_risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "risk_score": 0-100,
    "executive_summary": "2-3 sentence summary for leadership",
    "critical_findings": [
        {{"cve_id": "...", "reason": "why this is critical", "immediate_action": "what to do"}}
    ],
    "prioritized_remediation": [
        {{"priority": 1, "action": "...", "impact": "..."}}
    ],
    "security_improvements": ["list of general improvements"],
    "confidence": 0.0-1.0
}}"""

        response = self._call_claude(prompt)

        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            data = {"executive_summary": response, "confidence": 0.5, "overall_risk_level": "MEDIUM"}

        recommendations = []
        for item in data.get("prioritized_remediation", []):
            if isinstance(item, dict):
                recommendations.append(f"[P{item.get('priority', '?')}] {item.get('action', '')}")
            else:
                recommendations.append(str(item))

        return AIAnalysisResult(
            analysis_type=AnalysisType.RISK_ASSESSMENT.value,
            input_summary=f"Vulns: {len(vulnerabilities)}, Correlations: {len(correlations)}",
            analysis=data.get("executive_summary", response),
            confidence=data.get("confidence", 0.7),
            recommendations=recommendations + data.get("security_improvements", []),
            risk_level=data.get("overall_risk_level", "MEDIUM"),
            raw_response=response,
        )

    def triage_events(self, events: List[CDREvent]) -> AIAnalysisResult:
        """AI-powered triage of CDR events to identify most critical ones."""
        events_data = [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "description": e.description,
                "mitre_techniques": e.mitre_techniques,
                "container": e.container_name,
                "pod": e.pod_name,
                "timestamp": e.timestamp,
            }
            for e in events[:30]
        ]

        prompt = f"""Triage these container runtime security events. Identify the most critical ones requiring immediate attention.

Events ({len(events)} total, showing first 30):
{json.dumps(events_data, indent=2)}

Analyze each event and categorize by:
1. Attack likelihood (is this a real attack or noise?)
2. Severity (what's the potential impact?)
3. Urgency (how quickly must we respond?)

Respond in JSON format:
{{
    "critical_events": [
        {{"event_id": "...", "reason": "why critical", "attack_type": "...", "recommended_response": "..."}}
    ],
    "suspicious_events": [
        {{"event_id": "...", "reason": "why suspicious", "investigation_steps": ["..."]}}
    ],
    "likely_benign": [
        {{"event_id": "...", "reason": "why likely benign"}}
    ],
    "overall_threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "summary": "Brief summary of the threat landscape",
    "confidence": 0.0-1.0
}}"""

        response = self._call_claude(prompt)

        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            data = {"summary": response, "confidence": 0.5, "overall_threat_level": "MEDIUM"}

        recommendations = []
        for event in data.get("critical_events", []):
            if isinstance(event, dict):
                recommendations.append(f"[CRITICAL] {event.get('event_id', '?')}: {event.get('recommended_response', '')}")

        return AIAnalysisResult(
            analysis_type=AnalysisType.TRIAGE_EVENTS.value,
            input_summary=f"Triaged {len(events)} events",
            analysis=data.get("summary", response),
            confidence=data.get("confidence", 0.7),
            recommendations=recommendations,
            risk_level=data.get("overall_threat_level", "MEDIUM"),
            raw_response=response,
        )


def format_analysis_result(result: AIAnalysisResult, verbose: bool = False) -> str:
    """Format an analysis result for CLI output."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"AI Analysis: {result.analysis_type.upper()}")
    lines.append("=" * 70)
    lines.append(f"Input: {result.input_summary}")
    lines.append(f"Confidence: {result.confidence:.0%}")
    if result.risk_level:
        lines.append(f"Risk Level: {result.risk_level}")
    lines.append("")
    lines.append("ANALYSIS:")
    lines.append(result.analysis)
    lines.append("")

    if result.recommendations:
        lines.append("RECOMMENDATIONS:")
        for rec in result.recommendations:
            if rec:
                lines.append(f"  - {rec}")
        lines.append("")

    if result.suggested_policy:
        lines.append("SUGGESTED POLICY:")
        import yaml
        lines.append(yaml.dump(result.suggested_policy, default_flow_style=False))

    if verbose:
        lines.append("RAW RESPONSE:")
        lines.append(result.raw_response)

    return "\n".join(lines)
