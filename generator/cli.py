#!/usr/bin/env python3
"""CLI for Qualys CRS policy generator."""
import argparse
import sys
import os
import yaml
from typing import List

from config import QualysConfig, PolicyConfig, THREAT_INDICATORS
from qualys_client import QualysClient
from policy_generator import PolicyGenerator, TracingPolicy, FimPolicy
from qualys_cdr_client import QualysCDRConfig, QualysCDRClient


def generate_base_detection_policies(generator: PolicyGenerator) -> List[TracingPolicy]:
    """Generate standard threat detection policies."""
    policies = []

    # Reverse shell detection
    policies.append(generator.generate_execve_policy(
        name="detect-reverse-shell-tools",
        binaries=THREAT_INDICATORS["reverse_shells"]["binaries"],
        action="Post",
        mitre_technique="T1059",
        category="execution",
    ))

    # Crypto miner detection
    policies.append(generator.generate_execve_policy(
        name="detect-crypto-miners",
        binaries=THREAT_INDICATORS["crypto_miners"]["binaries"],
        action="Post",
        mitre_technique="T1496",
        category="resource-hijacking",
    ))

    policies.append(generator.generate_network_policy(
        name="detect-mining-pool-connections",
        ports=THREAT_INDICATORS["crypto_miners"]["ports"],
        action="Post",
        mitre_technique="T1496",
        category="resource-hijacking",
    ))

    # Reconnaissance tools
    policies.append(generator.generate_execve_policy(
        name="detect-recon-tools",
        binaries=THREAT_INDICATORS["recon_tools"]["binaries"],
        action="Post",
        mitre_technique="T1021",
        category="lateral-movement",
    ))

    # Credential file access
    all_creds = (
        THREAT_INDICATORS["credential_files"]["linux"] +
        THREAT_INDICATORS["credential_files"]["ssh"] +
        THREAT_INDICATORS["credential_files"]["cloud"]
    )
    policies.append(generator.generate_file_access_policy(
        name="detect-credential-access",
        file_paths=all_creds,
        match_type="Postfix",
        action="Post",
        mitre_technique="T1552",
        category="credential-access",
    ))

    # Persistence paths monitoring
    all_persistence = (
        THREAT_INDICATORS["persistence_paths"]["cron"] +
        THREAT_INDICATORS["persistence_paths"]["systemd"] +
        THREAT_INDICATORS["persistence_paths"]["init"]
    )
    policies.append(generator.generate_file_access_policy(
        name="detect-persistence-writes",
        file_paths=all_persistence,
        match_type="Prefix",
        write_only=True,
        action="Post",
        mitre_technique="T1053",
        category="persistence",
    ))

    return policies


def generate_base_prevention_policies(generator: PolicyGenerator) -> List[TracingPolicy]:
    """Generate standard threat prevention (blocking) policies."""
    policies = []

    # Block reverse shell tools
    policies.append(generator.generate_execve_policy(
        name="block-reverse-shell-tools",
        binaries=THREAT_INDICATORS["reverse_shells"]["binaries"],
        action="Sigkill",
        mitre_technique="T1059",
        category="execution",
    ))

    # Block crypto miners
    policies.append(generator.generate_execve_policy(
        name="block-crypto-miners",
        binaries=THREAT_INDICATORS["crypto_miners"]["binaries"],
        action="Sigkill",
        mitre_technique="T1496",
        category="resource-hijacking",
    ))

    policies.append(generator.generate_network_policy(
        name="block-mining-pool-connections",
        ports=THREAT_INDICATORS["crypto_miners"]["ports"],
        action="Sigkill",
        mitre_technique="T1496",
        category="resource-hijacking",
    ))

    # Block container escape syscalls
    policies.append(generator.generate_syscall_policy(
        name="block-namespace-manipulation",
        syscall="sys_unshare",
        args=[{"index": 0, "type": "int"}],
        selectors=[{
            "matchNamespaceChanges": [{
                "operator": "In",
                "values": ["User", "Mnt", "Pid"],
            }],
            "matchActions": [{"action": "Sigkill"}],
        }],
        mitre_technique="T1611",
        category="container-escape",
    ))

    policies.append(generator.generate_syscall_policy(
        name="block-setns",
        syscall="sys_setns",
        args=[
            {"index": 0, "type": "int"},
            {"index": 1, "type": "int"},
        ],
        selectors=[{"matchActions": [{"action": "Sigkill"}]}],
        mitre_technique="T1611",
        category="container-escape",
    ))

    return policies


def generate_fim_policies(generator: PolicyGenerator) -> List[FimPolicy]:
    """Generate standard FIM policies."""
    policies = []

    # Critical system files
    policies.append(generator.generate_fim_policy(
        name="fim-system-files",
        paths=THREAT_INDICATORS["credential_files"]["linux"],
        operation="file-write",
        category="integrity-monitoring",
    ))

    # SSH configuration
    policies.append(generator.generate_fim_policy(
        name="fim-ssh-keys",
        paths=["/etc/ssh", "/root/.ssh"],
        operation="file-write",
        category="credential-access",
    ))

    # Persistence paths
    all_persistence = (
        THREAT_INDICATORS["persistence_paths"]["cron"] +
        THREAT_INDICATORS["persistence_paths"]["systemd"] +
        THREAT_INDICATORS["persistence_paths"]["init"]
    )
    policies.append(generator.generate_fim_policy(
        name="fim-persistence-paths",
        paths=all_persistence,
        operation="file-write",
        category="persistence",
    ))

    return policies


def _generate_vuln_policy(vuln, events, action: str):
    """Generate a TracingPolicy for a specific vulnerability based on its characteristics."""
    from datetime import datetime

    cve = vuln.cve_id or vuln.vuln_id
    safe_name = cve.lower().replace(".", "-").replace("_", "-")

    base_policy = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicy",
        "metadata": {
            "name": f"vuln-{safe_name}-{datetime.utcnow().strftime('%Y%m%d')}",
            "labels": {
                "generated-by": "qualys-vuln-correlation",
                "vulnerability": cve,
                "severity": vuln.severity_string.lower(),
            },
            "annotations": {
                "cvss-score": str(vuln.cvss_score or ""),
                "package": vuln.package_name,
                "actively-exploited": str(vuln.actively_exploited).lower(),
            },
        },
        "spec": {"kprobes": []},
    }

    if vuln.package_path:
        base_policy["spec"]["kprobes"].append({
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{
                "matchArgs": [{
                    "index": 0,
                    "operator": "Postfix",
                    "values": [vuln.package_path],
                }],
                "matchActions": [{"action": action}],
            }],
        })

    for tech in vuln.mitre_techniques:
        if tech.startswith("T1611"):
            base_policy["spec"]["kprobes"].append({
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
            })
        elif tech.startswith("T1059"):
            base_policy["spec"]["kprobes"].append({
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
            })

    if not base_policy["spec"]["kprobes"]:
        base_policy["spec"]["kprobes"].append({
            "call": "sys_execve",
            "syscall": True,
            "args": [{"index": 0, "type": "string"}],
            "selectors": [{"matchActions": [{"action": action}]}],
        })

    return base_policy


def main():
    parser = argparse.ArgumentParser(
        description="Generate Qualys TracingPolicy and FimPolicy CRDs"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate policies")
    gen_parser.add_argument(
        "--type",
        choices=["detection", "prevention", "fim", "all"],
        default="all",
        help="Type of policies to generate",
    )
    gen_parser.add_argument(
        "--output", "-o",
        default="./generated-policies",
        help="Output directory for generated policies",
    )
    gen_parser.add_argument(
        "--namespace", "-n",
        help="Kubernetes namespace for namespaced policies",
    )
    gen_parser.add_argument(
        "--single-file",
        action="store_true",
        help="Combine all policies into a single file",
    )

    # Fetch from Qualys command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch data from Qualys and generate policies")
    fetch_parser.add_argument(
        "--output", "-o",
        default="./qualys-policies",
        help="Output directory for generated policies",
    )
    fetch_parser.add_argument(
        "--severity-min",
        type=int,
        default=3,
        help="Minimum severity level (1-5)",
    )
    fetch_parser.add_argument(
        "--enforcement",
        action="store_true",
        help="Generate enforcement (blocking) policies instead of detection",
    )

    # List indicators command
    list_parser = subparsers.add_parser("list", help="List available threat indicators")
    list_parser.add_argument(
        "--category",
        help="Filter by category",
    )

    # CDR integration command
    cdr_parser = subparsers.add_parser("cdr", help="Generate policies from Qualys CDR events")
    cdr_parser.add_argument(
        "--platform", "-p",
        default="qualysguard.qg2.apps.qualys.com",
        help="Qualys platform URL (e.g., qualysguard.qg1.apps.qualys.ca for Canada)",
    )
    cdr_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Look back period in hours",
    )
    cdr_parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter by severity",
    )
    cdr_parser.add_argument(
        "--output", "-o",
        default="./cdr-generated-policies",
        help="Output directory",
    )
    cdr_parser.add_argument(
        "--action",
        choices=["Post", "Sigkill"],
        default="Post",
        help="Action for generated policies (Post=audit, Sigkill=block)",
    )

    vulns_parser = subparsers.add_parser("vulns", help="Vulnerability correlation and analytics")
    vulns_subparsers = vulns_parser.add_subparsers(dest="vulns_command", help="Vulnerability commands")

    vulns_fetch_parser = vulns_subparsers.add_parser("fetch", help="Fetch vulnerabilities from Qualys CS")
    vulns_fetch_parser.add_argument(
        "--severity-min", type=int, default=3,
        help="Minimum severity level (1-5)",
    )
    vulns_fetch_parser.add_argument(
        "--limit", type=int, default=100,
        help="Maximum number of images to scan",
    )
    vulns_fetch_parser.add_argument(
        "--running-only", action="store_true", default=True,
        help="Only include images with running containers",
    )
    vulns_fetch_parser.add_argument(
        "--output", "-o", default="./vulns.json",
        help="Output file path",
    )

    vulns_correlate_parser = vulns_subparsers.add_parser("correlate", help="Correlate vulns with runtime events")
    vulns_correlate_parser.add_argument(
        "--hours", type=int, default=24,
        help="Look back period for events in hours",
    )
    vulns_correlate_parser.add_argument(
        "--severity-min", type=int, default=3,
        help="Minimum vulnerability severity (1-5)",
    )
    vulns_correlate_parser.add_argument(
        "--output", "-o", default="./correlations.json",
        help="Output file path",
    )

    vulns_analytics_parser = vulns_subparsers.add_parser("analytics", help="Generate vulnerability analytics")
    vulns_analytics_parser.add_argument(
        "--hours", type=int, default=24,
        help="Look back period for events in hours",
    )
    vulns_analytics_parser.add_argument(
        "--top", type=int, default=10,
        help="Number of top vulnerabilities to show",
    )
    vulns_analytics_parser.add_argument(
        "--pareto", action="store_true",
        help="Include pareto analysis (vulns fixing 80%% of issues)",
    )
    vulns_analytics_parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON instead of text",
    )

    vulns_export_parser = vulns_subparsers.add_parser("export", help="Export data for external scripts")
    vulns_export_parser.add_argument(
        "--type", choices=["vulns", "events", "correlations", "all"], default="all",
        help="Type of data to export",
    )
    vulns_export_parser.add_argument(
        "--format", choices=["json", "csv"], default="json",
        help="Output format",
    )
    vulns_export_parser.add_argument(
        "--hours", type=int, default=24,
        help="Look back period for events in hours",
    )
    vulns_export_parser.add_argument(
        "--output", "-o", default="./data.json",
        help="Output file path",
    )

    vulns_policy_parser = vulns_subparsers.add_parser("policy", help="Generate policies from correlated vulns")
    vulns_policy_parser.add_argument(
        "--hours", type=int, default=24,
        help="Look back period for events in hours",
    )
    vulns_policy_parser.add_argument(
        "--exploited-only", action="store_true",
        help="Only generate policies for actively exploited vulns",
    )
    vulns_policy_parser.add_argument(
        "--action", choices=["Post", "Sigkill"], default="Sigkill",
        help="Action for generated policies",
    )
    vulns_policy_parser.add_argument(
        "--output", "-o", default="./vuln-policies",
        help="Output directory for policies",
    )

    vulns_ai_parser = vulns_subparsers.add_parser("ai", help="AI-powered vulnerability analysis")
    vulns_ai_parser.add_argument(
        "--explain", metavar="CVE",
        help="Get AI explanation of a CVE (e.g., CVE-2024-21626)",
    )
    vulns_ai_parser.add_argument(
        "--validate", action="store_true",
        help="Validate if recent events indicate exploitation",
    )
    vulns_ai_parser.add_argument(
        "--suggest-policy", metavar="CVE",
        help="Generate AI-suggested TracingPolicy for a CVE",
    )
    vulns_ai_parser.add_argument(
        "--risk-assessment", action="store_true",
        help="Get AI risk assessment of current vulnerabilities",
    )
    vulns_ai_parser.add_argument(
        "--triage", action="store_true",
        help="AI triage of recent CDR events",
    )
    vulns_ai_parser.add_argument(
        "--hours", type=int, default=24,
        help="Look back period for events",
    )
    vulns_ai_parser.add_argument(
        "--action", choices=["Post", "Sigkill"], default="Post",
        help="Action for suggested policies",
    )
    vulns_ai_parser.add_argument(
        "--json", action="store_true",
        help="Output raw JSON response",
    )
    vulns_ai_parser.add_argument(
        "--output", "-o",
        help="Save output to file",
    )

    events_parser = subparsers.add_parser("events", help="Security event catalog and policy generation")
    events_subparsers = events_parser.add_subparsers(dest="events_command", help="Event commands")

    events_list_parser = events_subparsers.add_parser("list", help="List security events")
    events_list_parser.add_argument(
        "--category",
        help="Filter by category (persistence, execution, credential_access, etc.)",
    )
    events_list_parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter by severity",
    )

    events_show_parser = events_subparsers.add_parser("show", help="Show event details")
    events_show_parser.add_argument("event_id", help="Event ID (e.g., QCR001)")

    events_generate_parser = events_subparsers.add_parser("generate", help="Generate TracingPolicies")
    events_generate_parser.add_argument(
        "--event-id",
        help="Generate policy for specific event ID",
    )
    events_generate_parser.add_argument(
        "--category",
        help="Generate policies for all events in category",
    )
    events_generate_parser.add_argument(
        "--all", action="store_true",
        help="Generate policies for all 49 events",
    )
    events_generate_parser.add_argument(
        "--action", choices=["Post", "Sigkill"], default="Post",
        help="Action for generated policies",
    )
    events_generate_parser.add_argument(
        "--output", "-o", default="./event-policies",
        help="Output directory",
    )

    events_ai_parser = events_subparsers.add_parser("ai-analyze", help="AI analysis of security events")
    events_ai_parser.add_argument("event_id", help="Event ID to analyze (e.g., QCR001)")
    events_ai_parser.add_argument(
        "--generate-policy", action="store_true",
        help="Generate AI-enhanced policy for this event",
    )
    events_ai_parser.add_argument(
        "--json", action="store_true",
        help="Output raw JSON",
    )

    drift_parser = subparsers.add_parser("drift", help="Container drift management policies")
    drift_subparsers = drift_parser.add_subparsers(dest="drift_command", help="Drift commands")

    drift_list_parser = drift_subparsers.add_parser("list", help="List drift policy types")

    drift_generate_parser = drift_subparsers.add_parser("generate", help="Generate drift policies")
    drift_generate_parser.add_argument(
        "--mode", choices=["detect", "enforce"], default="detect",
        help="detect=alert only, enforce=block/kill",
    )
    drift_generate_parser.add_argument(
        "--namespace", "-n",
        help="Kubernetes namespace to apply policies to",
    )
    drift_generate_parser.add_argument(
        "--output", "-o", default="./drift-policies",
        help="Output directory",
    )
    drift_generate_parser.add_argument(
        "--policy", choices=["all", "drift", "binary-paths", "package-managers", "download-tools"],
        default="all",
        help="Specific policy to generate",
    )

    args = parser.parse_args()

    if args.command == "generate":
        config = PolicyConfig(
            output_dir=args.output,
            namespace=args.namespace,
        )
        generator = PolicyGenerator(config)

        all_policies = []

        if args.type in ["detection", "all"]:
            detection_policies = generate_base_detection_policies(generator)
            all_policies.extend(detection_policies)
            print(f"Generated {len(detection_policies)} detection policies")

        if args.type in ["prevention", "all"]:
            prevention_policies = generate_base_prevention_policies(generator)
            all_policies.extend(prevention_policies)
            print(f"Generated {len(prevention_policies)} prevention policies")

        if args.type in ["fim", "all"]:
            fim_policies = generate_fim_policies(generator)
            all_policies.extend(fim_policies)
            print(f"Generated {len(fim_policies)} FIM policies")

        paths = generator.save_policies(all_policies, single_file=args.single_file)
        print(f"\nSaved policies to: {args.output}")
        for path in paths:
            print(f"  - {path}")

    elif args.command == "fetch":
        qualys_config = QualysConfig.from_env()

        if not qualys_config.username or not qualys_config.password:
            print("Error: QUALYS_USERNAME and QUALYS_PASSWORD environment variables required")
            print("Set them with:")
            print("  export QUALYS_USERNAME=your_username")
            print("  export QUALYS_PASSWORD=your_password")
            print("  export QUALYS_API_URL=https://qualysapi.qualys.com  # optional")
            sys.exit(1)

        client = QualysClient(qualys_config)

        policy_config = PolicyConfig(
            output_dir=args.output,
            enforcement_mode=args.enforcement,
        )
        generator = PolicyGenerator(policy_config)

        print("Fetching threat data from Qualys...")
        indicators = client.get_knowledgebase(severity_min=args.severity_min)
        print(f"Found {len(indicators)} threat indicators")

        policies = generator.generate_from_threat_indicators(
            [{"qid": i.qid, "mitre_techniques": i.mitre_techniques} for i in indicators]
        )

        if policies:
            paths = generator.save_policies(policies)
            print(f"\nGenerated {len(policies)} policies from Qualys data")
            print(f"Saved to: {args.output}")
        else:
            print("No policies generated from Qualys data")

    elif args.command == "list":
        print("Available Threat Indicators:\n")
        for category, indicators in THREAT_INDICATORS.items():
            if args.category and args.category != category:
                continue
            print(f"[{category}]")
            for indicator_type, values in indicators.items():
                if isinstance(values, list):
                    print(f"  {indicator_type}: {', '.join(str(v) for v in values[:5])}")
                    if len(values) > 5:
                        print(f"    ... and {len(values) - 5} more")
            print()

    elif args.command == "cdr":
        # Qualys CDR integration
        print("=" * 50)
        print("Qualys CDR Policy Generator")
        print("=" * 50)
        print("")
        print("Qualys Platform URLs:")
        print("  US Platform 1:  qualysapi.qualys.com")
        print("  US Platform 2:  qualysguard.qg2.apps.qualys.com")
        print("  US Platform 3:  qualysguard.qg3.apps.qualys.com")
        print("  Canada:         qualysguard.qg1.apps.qualys.ca")
        print("  EU Platform 1:  qualysguard.qualys.eu")
        print("  EU Platform 2:  qualysguard.qg2.apps.qualys.eu")
        print("  India:          qualysguard.qg1.apps.qualys.in")
        print("  UAE:            qualysguard.qg1.apps.qualys.ae")
        print("  Australia:      qualysguard.qg1.apps.qualys.com.au")
        print("")

        cdr_config = QualysCDRConfig.from_env()
        if args.platform:
            cdr_config.platform_url = args.platform

        if not cdr_config.username or not cdr_config.password:
            print("Error: Set QUALYS_USERNAME and QUALYS_PASSWORD environment variables")
            print("")
            print("  export QUALYS_USERNAME=your_username")
            print("  export QUALYS_PASSWORD=your_password")
            print("  export QUALYS_PLATFORM_URL=qualysguard.qg1.apps.qualys.ca")
            sys.exit(1)

        client = QualysCDRClient(cdr_config)

        print(f"Using platform: {cdr_config.platform_url}")
        print(f"CDR API: {cdr_config.cdr_url}/cdr/detections")
        print(f"CS API:  {cdr_config.cs_url}/crs/events")
        print("")

        print(f"Fetching container detection events from last {args.hours} hours...")
        events = client.get_cdr_detections(
            hours=args.hours,
            severity=args.severity,
            resource_type="container",
        )

        print(f"Found {len(events)} container detection events")

        if events:
            print("\nDetection breakdown:")
            by_severity = {}
            by_technique = {}
            for event in events:
                by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
                for tech in event.mitre_techniques:
                    by_technique[tech] = by_technique.get(tech, 0) + 1

            for sev, count in sorted(by_severity.items()):
                print(f"  {sev}: {count}")

            if by_technique:
                print("\nMITRE ATT&CK techniques:")
                for tech, count in sorted(by_technique.items(), key=lambda x: -x[1])[:10]:
                    print(f"  {tech}: {count}")

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
            print(f"\nApply with: kubectl apply -f {args.output}/")
        else:
            print("No container detection events found.")
            print("Ensure Qualys CDR is configured and generating detections.")
            print("")
            print("Alternative: Generate base policies instead:")
            print("  python cli.py generate --type all")

    elif args.command == "vulns":
        from vuln_models import ContainerVulnerability
        from vuln_correlator import VulnCorrelator
        from vuln_analytics import (
            generate_report, format_report_text, export_data,
            pareto_analysis, highest_risk_vulns
        )
        import json

        cdr_config = QualysCDRConfig.from_env()

        if not cdr_config.username or not cdr_config.password:
            print("Error: Set QUALYS_USERNAME and QUALYS_PASSWORD environment variables")
            sys.exit(1)

        client = QualysCDRClient(cdr_config)

        if args.vulns_command == "fetch":
            print(f"Fetching vulnerabilities (severity >= {args.severity_min})...")
            vulns = client.get_all_vulnerabilities(
                severity_min=args.severity_min,
                limit=args.limit,
                running_only=args.running_only,
            )
            print(f"Found {len(vulns)} vulnerabilities")

            vuln_data = [
                {
                    "vuln_id": v.vuln_id,
                    "cve_id": v.cve_id,
                    "severity": v.severity_string,
                    "cvss_score": v.cvss_score,
                    "image_id": v.image_id,
                    "image_name": v.image_name,
                    "package_name": v.package_name,
                    "exploitable": v.exploitable,
                    "actively_exploited": v.actively_exploited,
                    "risk_score": v.risk_score(),
                }
                for v in vulns
            ]

            with open(args.output, "w") as f:
                json.dump(vuln_data, f, indent=2)
            print(f"Saved to {args.output}")

        elif args.vulns_command == "correlate":
            print(f"Fetching vulnerabilities...")
            vulns = client.get_all_vulnerabilities(severity_min=args.severity_min)
            print(f"Found {len(vulns)} vulnerabilities")

            print(f"Fetching CDR events from last {args.hours} hours...")
            events = client.get_cdr_detections(hours=args.hours, resource_type="container")
            print(f"Found {len(events)} events")

            print("Correlating...")
            correlator = VulnCorrelator()
            correlations = correlator.correlate(vulns, events)
            print(f"Found {len(correlations)} correlations")

            corr_data = [
                {
                    "vuln_id": c.vulnerability.vuln_id,
                    "cve_id": c.vulnerability.cve_id,
                    "severity": c.vulnerability.severity_string,
                    "event_count": len(c.events),
                    "confidence": c.confidence,
                    "matched_by": c.matched_by,
                    "combined_risk_score": c.combined_risk_score,
                }
                for c in correlations
            ]

            with open(args.output, "w") as f:
                json.dump(corr_data, f, indent=2)
            print(f"Saved to {args.output}")

        elif args.vulns_command == "analytics":
            print("Fetching data...")
            vulns = client.get_all_vulnerabilities(severity_min=3)
            events = client.get_cdr_detections(hours=args.hours, resource_type="container")
            containers = client.get_running_containers()

            correlator = VulnCorrelator()
            correlations = correlator.correlate(vulns, events)

            report = generate_report(vulns, correlations, containers)

            if args.json:
                print(json.dumps(report.to_dict(), indent=2))
            else:
                print(format_report_text(report))

        elif args.vulns_command == "export":
            print("Fetching data...")
            vulns = client.get_all_vulnerabilities(severity_min=3)
            events = client.get_cdr_detections(hours=args.hours, resource_type="container")
            containers = client.get_running_containers()

            correlator = VulnCorrelator()
            correlations = correlator.correlate(vulns, events)
            report = generate_report(vulns, correlations, containers)

            output = export_data(vulns, events, correlations, report, args.format)

            with open(args.output, "w") as f:
                f.write(output)
            print(f"Exported to {args.output}")

        elif args.vulns_command == "policy":
            from datetime import datetime as dt

            print("Fetching data for policy generation...")
            vulns = client.get_all_vulnerabilities(severity_min=3)
            events = client.get_cdr_detections(hours=args.hours, resource_type="container")

            correlator = VulnCorrelator()
            correlations = correlator.correlate(vulns, events)

            if args.exploited_only:
                correlations = [c for c in correlations if c.vulnerability.actively_exploited]

            print(f"Generating policies for {len(correlations)} correlated vulnerabilities...")

            os.makedirs(args.output, exist_ok=True)
            policy_count = 0

            cve_policies = {}
            for corr in correlations:
                vuln = corr.vulnerability
                cve = vuln.cve_id or vuln.vuln_id

                if cve in cve_policies:
                    continue

                policy = _generate_vuln_policy(vuln, corr.events, args.action)
                if policy:
                    cve_policies[cve] = policy
                    name = policy["metadata"]["name"]
                    filepath = os.path.join(args.output, f"{name}.yaml")
                    with open(filepath, "w") as f:
                        yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
                    print(f"  Generated: {filepath}")
                    policy_count += 1

            print(f"\nGenerated {policy_count} policies in {args.output}")
            print(f"Apply with: kubectl apply -f {args.output}/")

        elif args.vulns_command == "ai":
            try:
                from vuln_ai_analyzer import VulnAIAnalyzer, format_analysis_result
            except ImportError as e:
                print(f"Error: {e}")
                print("Install anthropic: pip install anthropic")
                sys.exit(1)

            try:
                analyzer = VulnAIAnalyzer()
            except ValueError as e:
                print(f"Error: {e}")
                print("Set ANTHROPIC_API_KEY environment variable")
                sys.exit(1)

            result = None

            if args.explain:
                print(f"Analyzing {args.explain}...")
                result = analyzer.explain_cve(args.explain)

            elif args.suggest_policy:
                print(f"Generating policy for {args.suggest_policy}...")
                vulns = client.get_all_vulnerabilities(severity_min=1)
                target_vuln = None
                for v in vulns:
                    if v.cve_id == args.suggest_policy or v.vuln_id == args.suggest_policy:
                        target_vuln = v
                        break

                if not target_vuln:
                    from vuln_models import ContainerVulnerability
                    target_vuln = ContainerVulnerability(
                        vuln_id=args.suggest_policy,
                        cve_id=args.suggest_policy if args.suggest_policy.startswith("CVE") else None,
                        severity=4,
                        cvss_score=None,
                        image_id="",
                        image_name="",
                        container_ids=[],
                        package_name="",
                        package_path="",
                    )

                result = analyzer.suggest_policy(target_vuln, args.action)

            elif args.validate:
                print("Fetching vulnerabilities and events for validation...")
                vulns = client.get_all_vulnerabilities(severity_min=3)
                events = client.get_cdr_detections(hours=args.hours, resource_type="container")

                if not vulns or not events:
                    print("No vulnerabilities or events found to validate")
                    sys.exit(0)

                correlator = VulnCorrelator()
                correlations = correlator.correlate(vulns, events)

                if correlations:
                    top_corr = max(correlations, key=lambda c: len(c.events))
                    result = analyzer.validate_exploit(top_corr.vulnerability, top_corr.events)
                else:
                    print("No correlations found to validate")
                    sys.exit(0)

            elif args.risk_assessment:
                print("Performing AI risk assessment...")
                vulns = client.get_all_vulnerabilities(severity_min=3)
                events = client.get_cdr_detections(hours=args.hours, resource_type="container")

                correlator = VulnCorrelator()
                correlations = correlator.correlate(vulns, events)

                result = analyzer.assess_risk(vulns, correlations)

            elif args.triage:
                print(f"Triaging events from last {args.hours} hours...")
                events = client.get_cdr_detections(hours=args.hours, resource_type="container")

                if not events:
                    print("No events found to triage")
                    sys.exit(0)

                result = analyzer.triage_events(events)

            else:
                print("Specify an AI analysis option: --explain, --validate, --suggest-policy, --risk-assessment, or --triage")
                sys.exit(1)

            if result:
                if args.json:
                    output = result.raw_response
                else:
                    output = format_analysis_result(result)

                print(output)

                if args.output:
                    with open(args.output, "w") as f:
                        f.write(output)
                    print(f"\nSaved to {args.output}")

        else:
            vulns_parser.print_help()

    elif args.command == "events":
        from event_catalog import (
            SECURITY_EVENTS, get_event_by_id, get_events_by_category,
            list_events, generate_tracing_policy, generate_all_policies
        )

        if args.events_command == "list":
            print(list_events(args.category, args.severity))

        elif args.events_command == "show":
            event = get_event_by_id(args.event_id.upper())
            if not event:
                for key, e in SECURITY_EVENTS.items():
                    if e.id.upper() == args.event_id.upper():
                        event = e
                        break

            if event:
                print(f"Event ID:     {event.id}")
                print(f"Name:         {event.name}")
                print(f"Category:     {event.category}")
                print(f"Severity:     {event.severity}")
                print(f"Description:  {event.description}")
                print(f"MITRE:        {', '.join(event.mitre_techniques)}")
                print(f"Syscalls:     {', '.join(event.syscalls)}")
                if event.file_patterns:
                    print(f"File Patterns: {', '.join(event.file_patterns[:5])}")
                if event.process_patterns:
                    print(f"Processes:    {', '.join(event.process_patterns[:5])}")
                if event.args_patterns:
                    print(f"Args:         {', '.join(event.args_patterns[:5])}")
                print(f"Detection:    {event.detection_logic}")
            else:
                print(f"Event not found: {args.event_id}")
                sys.exit(1)

        elif args.events_command == "generate":
            os.makedirs(args.output, exist_ok=True)

            if args.all:
                files = generate_all_policies(args.action, args.output)
                print(f"Generated {len(files)} policies in {args.output}")

            elif args.event_id:
                event = get_event_by_id(args.event_id.upper())
                if event:
                    policy = generate_tracing_policy(event, args.action)
                    filename = f"{event.id.lower()}.yaml"
                    filepath = os.path.join(args.output, filename)
                    with open(filepath, "w") as f:
                        yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
                    print(f"Generated: {filepath}")
                else:
                    print(f"Event not found: {args.event_id}")
                    sys.exit(1)

            elif args.category:
                events = get_events_by_category(args.category)
                if events:
                    for event in events:
                        policy = generate_tracing_policy(event, args.action)
                        filename = f"{event.id.lower()}.yaml"
                        filepath = os.path.join(args.output, filename)
                        with open(filepath, "w") as f:
                            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
                        print(f"Generated: {filepath}")
                    print(f"\nGenerated {len(events)} policies for category '{args.category}'")
                else:
                    print(f"No events found in category: {args.category}")
                    sys.exit(1)
            else:
                print("Specify --all, --event-id, or --category")
                sys.exit(1)

        elif args.events_command == "ai-analyze":
            event = get_event_by_id(args.event_id.upper())
            if not event:
                print(f"Event not found: {args.event_id}")
                sys.exit(1)

            try:
                from vuln_ai_analyzer import VulnAIAnalyzer
            except ImportError as e:
                print(f"Error: {e}")
                print("Install anthropic: pip install anthropic")
                sys.exit(1)

            try:
                analyzer = VulnAIAnalyzer()
            except ValueError as e:
                print(f"Error: {e}")
                sys.exit(1)

            context = {
                "event_id": event.id,
                "name": event.name,
                "description": event.description,
                "category": event.category,
                "mitre_techniques": event.mitre_techniques,
                "syscalls": event.syscalls,
                "file_patterns": event.file_patterns,
                "process_patterns": event.process_patterns,
            }

            print(f"Analyzing security event {event.id}: {event.name}...")

            prompt = f"""Analyze this container security event type and provide detection recommendations:

Event: {event.name}
Category: {event.category}
Description: {event.description}
MITRE Techniques: {', '.join(event.mitre_techniques)}
Syscalls: {', '.join(event.syscalls)}
File Patterns: {', '.join(event.file_patterns[:5]) if event.file_patterns else 'N/A'}
Process Patterns: {', '.join(event.process_patterns[:5]) if event.process_patterns else 'N/A'}

Provide:
1. Detailed explanation of this attack technique
2. How it manifests in containerized environments
3. Key indicators to monitor
4. Recommended TracingPolicy selectors for accurate detection
5. False positive reduction strategies

Respond in JSON format:
{{
    "technique_explanation": "...",
    "container_context": "...",
    "key_indicators": ["..."],
    "recommended_selectors": ["..."],
    "false_positive_strategies": ["..."],
    "confidence": 0.0-1.0
}}"""

            result = analyzer._call_claude(prompt)

            if args.json:
                print(result)
            else:
                print("=" * 70)
                print(f"AI Analysis: {event.name}")
                print("=" * 70)
                try:
                    import json as json_mod
                    data = json_mod.loads(result)
                    print(f"\nTechnique Explanation:")
                    print(f"  {data.get('technique_explanation', 'N/A')}")
                    print(f"\nContainer Context:")
                    print(f"  {data.get('container_context', 'N/A')}")
                    print(f"\nKey Indicators:")
                    for ind in data.get('key_indicators', []):
                        print(f"  - {ind}")
                    print(f"\nRecommended Selectors:")
                    for sel in data.get('recommended_selectors', []):
                        print(f"  - {sel}")
                    print(f"\nFalse Positive Strategies:")
                    for strat in data.get('false_positive_strategies', []):
                        print(f"  - {strat}")
                except:
                    print(result)

        else:
            events_parser.print_help()

    elif args.command == "drift":
        from drift_management import (
            list_drift_policies,
            generate_full_drift_policy_set,
            generate_drift_detection_policy,
            generate_drift_enforcement_policy,
            generate_binary_path_enforcement_policy,
            generate_package_manager_block_policy,
            generate_download_tool_block_policy,
        )

        if args.drift_command == "list":
            print(list_drift_policies())

        elif args.drift_command == "generate":
            os.makedirs(args.output, exist_ok=True)

            if args.policy == "all":
                files = generate_full_drift_policy_set(
                    args.output,
                    mode=args.mode,
                    namespace=args.namespace
                )
                print(f"Generated {len(files)} drift policies in {args.output}:")
                for f in files:
                    print(f"  {f}")

            else:
                policy = None
                filename = ""

                if args.policy == "drift":
                    if args.mode == "enforce":
                        policy = generate_drift_enforcement_policy(namespace=args.namespace)
                        filename = "drift-enforcement.yaml"
                    else:
                        policy = generate_drift_detection_policy(namespace=args.namespace)
                        filename = "drift-detection.yaml"

                elif args.policy == "binary-paths":
                    policy = generate_binary_path_enforcement_policy(namespace=args.namespace)
                    filename = "binary-path-enforcement.yaml"

                elif args.policy == "package-managers":
                    policy = generate_package_manager_block_policy(
                        mode=args.mode,
                        namespace=args.namespace
                    )
                    filename = f"package-manager-{args.mode}.yaml"

                elif args.policy == "download-tools":
                    policy = generate_download_tool_block_policy(
                        mode=args.mode,
                        namespace=args.namespace
                    )
                    filename = f"download-tool-{args.mode}.yaml"

                if policy:
                    filepath = os.path.join(args.output, filename)
                    with open(filepath, "w") as f:
                        yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
                    print(f"Generated: {filepath}")

        else:
            drift_parser.print_help()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
