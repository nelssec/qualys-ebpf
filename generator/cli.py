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


def main():
    parser = argparse.ArgumentParser(
        description="Generate Tetragon TracingPolicy and Qualys FimPolicy CRDs"
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

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
