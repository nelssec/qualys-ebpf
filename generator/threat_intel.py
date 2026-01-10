#!/usr/bin/env python3
"""Threat intelligence feed integration for dynamic IOC-based policy generation."""
import requests
import ipaddress
import yaml
import os
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime


@dataclass
class IOC:
    """Indicator of Compromise."""
    indicator: str
    ioc_type: str  # ip, domain, hash, port
    source: str
    severity: str = "high"
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ThreatIntelFeed:
    """Base class for threat intel feeds."""

    def __init__(self, name: str, url: str):
        self.name = name
        self.url = url

    def fetch(self) -> List[IOC]:
        raise NotImplementedError


class AbuseIPDBFeed(ThreatIntelFeed):
    """AbuseIPDB threat feed."""

    def __init__(self, api_key: str):
        super().__init__("AbuseIPDB", "https://api.abuseipdb.com/api/v2/blacklist")
        self.api_key = api_key

    def fetch(self, confidence_minimum: int = 90, limit: int = 1000) -> List[IOC]:
        """Fetch malicious IPs from AbuseIPDB."""
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": limit,
        }

        try:
            response = requests.get(self.url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            iocs = []
            for entry in data.get("data", []):
                iocs.append(IOC(
                    indicator=entry["ipAddress"],
                    ioc_type="ip",
                    source="AbuseIPDB",
                    severity="high" if entry.get("abuseConfidenceScore", 0) > 95 else "medium",
                    tags=entry.get("usageType", "").split(",") if entry.get("usageType") else [],
                ))
            return iocs
        except requests.RequestException as e:
            print(f"Error fetching AbuseIPDB: {e}")
            return []


class AlienVaultOTXFeed(ThreatIntelFeed):
    """AlienVault OTX threat feed."""

    def __init__(self, api_key: str):
        super().__init__("AlienVault OTX", "https://otx.alienvault.com/api/v1/pulses/subscribed")
        self.api_key = api_key

    def fetch(self, limit: int = 50) -> List[IOC]:
        """Fetch IOCs from AlienVault OTX pulses."""
        headers = {"X-OTX-API-KEY": self.api_key}
        params = {"limit": limit}

        try:
            response = requests.get(self.url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            iocs = []
            for pulse in data.get("results", []):
                for indicator in pulse.get("indicators", []):
                    ioc_type = self._map_indicator_type(indicator.get("type", ""))
                    if ioc_type:
                        iocs.append(IOC(
                            indicator=indicator["indicator"],
                            ioc_type=ioc_type,
                            source="AlienVault OTX",
                            severity="high",
                            tags=pulse.get("tags", []),
                        ))
            return iocs
        except requests.RequestException as e:
            print(f"Error fetching AlienVault OTX: {e}")
            return []

    def _map_indicator_type(self, otx_type: str) -> Optional[str]:
        type_map = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "hash",
            "FileHash-SHA1": "hash",
            "FileHash-SHA256": "hash",
        }
        return type_map.get(otx_type)


class EmergingThreatsFeed(ThreatIntelFeed):
    """Emerging Threats (Proofpoint) open feed."""

    def __init__(self):
        super().__init__("Emerging Threats", "https://rules.emergingthreats.net/blockrules")

    def fetch_compromised_ips(self) -> List[IOC]:
        """Fetch compromised IPs blocklist."""
        url = f"{self.url}/compromised-ips.txt"
        return self._fetch_ip_list(url, "compromised")

    def fetch_botnet_ips(self) -> List[IOC]:
        """Fetch botnet C2 IPs."""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
        return self._fetch_ip_list(url, "botnet")

    def _fetch_ip_list(self, url: str, tag: str) -> List[IOC]:
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            iocs = []
            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        ipaddress.ip_address(line)
                        iocs.append(IOC(
                            indicator=line,
                            ioc_type="ip",
                            source="Emerging Threats",
                            severity="high",
                            tags=[tag],
                        ))
                    except ValueError:
                        continue
            return iocs
        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return []


class TorExitNodesFeed(ThreatIntelFeed):
    """Tor exit nodes feed."""

    def __init__(self):
        super().__init__("Tor Project", "https://check.torproject.org/torbulkexitlist")

    def fetch(self) -> List[IOC]:
        """Fetch current Tor exit node IPs."""
        try:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()

            iocs = []
            for line in response.text.splitlines():
                line = line.strip()
                if line:
                    try:
                        ipaddress.ip_address(line)
                        iocs.append(IOC(
                            indicator=line,
                            ioc_type="ip",
                            source="Tor Project",
                            severity="medium",
                            tags=["tor", "anonymization"],
                        ))
                    except ValueError:
                        continue
            return iocs
        except requests.RequestException as e:
            print(f"Error fetching Tor exit nodes: {e}")
            return []


class FeodoTrackerFeed(ThreatIntelFeed):
    """Feodo Tracker for banking trojans and botnet C2."""

    def __init__(self):
        super().__init__("Feodo Tracker", "https://feodotracker.abuse.ch/downloads")

    def fetch_c2_ips(self) -> List[IOC]:
        """Fetch active C2 IPs."""
        url = f"{self.url}/ipblocklist.json"
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            iocs = []
            for entry in data:
                iocs.append(IOC(
                    indicator=entry.get("ip_address", ""),
                    ioc_type="ip",
                    source="Feodo Tracker",
                    severity="critical",
                    tags=[entry.get("malware", "unknown"), "c2", "botnet"],
                ))
            return iocs
        except requests.RequestException as e:
            print(f"Error fetching Feodo Tracker: {e}")
            return []


class URLhausFeed(ThreatIntelFeed):
    """URLhaus malware URL feed."""

    def __init__(self):
        super().__init__("URLhaus", "https://urlhaus.abuse.ch/downloads")

    def fetch_malware_urls(self) -> List[IOC]:
        """Fetch active malware URLs."""
        url = f"{self.url}/json/"
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            iocs = []
            for entry in data.get("urls", [])[:1000]:  # Limit to 1000
                if entry.get("url_status") == "online":
                    iocs.append(IOC(
                        indicator=entry.get("url", ""),
                        ioc_type="url",
                        source="URLhaus",
                        severity="critical",
                        tags=entry.get("tags", []) + ["malware"],
                    ))
            return iocs
        except requests.RequestException as e:
            print(f"Error fetching URLhaus: {e}")
            return []


class ThreatIntelManager:
    """Manager for aggregating threat intel from multiple feeds."""

    def __init__(self):
        self.feeds: List[ThreatIntelFeed] = []
        self.iocs: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash": set(),
            "port": set(),
        }

    def add_feed(self, feed: ThreatIntelFeed):
        self.feeds.append(feed)

    def add_open_feeds(self):
        """Add all open/free threat intel feeds."""
        self.add_feed(EmergingThreatsFeed())
        self.add_feed(TorExitNodesFeed())
        self.add_feed(FeodoTrackerFeed())
        self.add_feed(URLhausFeed())

    def refresh_all(self) -> Dict[str, int]:
        """Refresh IOCs from all feeds."""
        stats = {}

        for feed in self.feeds:
            feed_iocs = []

            # Handle feeds with multiple fetch methods
            if isinstance(feed, EmergingThreatsFeed):
                feed_iocs.extend(feed.fetch_compromised_ips())
                feed_iocs.extend(feed.fetch_botnet_ips())
            elif isinstance(feed, FeodoTrackerFeed):
                feed_iocs.extend(feed.fetch_c2_ips())
            elif isinstance(feed, URLhausFeed):
                feed_iocs.extend(feed.fetch_malware_urls())
            else:
                feed_iocs.extend(feed.fetch())

            for ioc in feed_iocs:
                self.iocs[ioc.ioc_type].add(ioc.indicator)

            stats[feed.name] = len(feed_iocs)

        return stats

    def generate_network_policy(self, name: str = "threat-intel-blocklist") -> Dict:
        """Generate Qualys NetworkPolicy from IOCs."""
        # Convert IPs to CIDRs
        cidrs = []
        for ip in self.iocs["ip"]:
            try:
                ipaddress.ip_address(ip)
                cidrs.append(f"{ip}/32")
            except ValueError:
                continue

        # Extract domains for FQDN rules
        domains = list(self.iocs["domain"])

        policy = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": name,
                "labels": {
                    "app.kubernetes.io/name": "qualys-network-security",
                    "policy-type": "threat-intel",
                    "auto-generated": "true",
                    "last-updated": datetime.utcnow().isoformat(),
                },
            },
            "spec": {
                "description": f"Auto-generated blocklist with {len(cidrs)} IPs and {len(domains)} domains",
                "endpointSelector": {},
                "egressDeny": [],
            },
        }

        # Add CIDR blocks (chunk to avoid policy size limits)
        if cidrs:
            # Split into chunks of 100 CIDRs
            for i in range(0, len(cidrs), 100):
                chunk = cidrs[i:i + 100]
                policy["spec"]["egressDeny"].append({"toCIDR": chunk})

        # Add domain blocks
        if domains:
            fqdn_rules = [{"matchName": d} for d in domains[:100]]  # Limit domains
            policy["spec"]["egressDeny"].append({"toFQDNs": fqdn_rules})

        return policy

    def generate_tracing_policy(self, name: str = "block-threat-intel-connections") -> Dict:
        """Generate Qualys TracingPolicy for blocking IOC connections."""
        # Extract ports from URLs if any
        suspicious_ports = set()
        for url in self.iocs["url"]:
            if ":" in url:
                try:
                    port = url.split(":")[2].split("/")[0]
                    if port.isdigit():
                        suspicious_ports.add(port)
                except (IndexError, ValueError):
                    continue

        policy = {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": name,
                "labels": {
                    "app.kubernetes.io/name": "qualys-network-security",
                    "threat.qualys.com/category": "threat-intel",
                    "auto-generated": "true",
                },
            },
            "spec": {
                "kprobes": [],
            },
        }

        # Add connection blocking for suspicious ports
        if suspicious_ports:
            policy["spec"]["kprobes"].append({
                "call": "sys_connect",
                "syscall": True,
                "args": [
                    {"index": 1, "type": "sockaddr"},
                ],
                "selectors": [{
                    "matchArgs": [{
                        "index": 1,
                        "operator": "DPort",
                        "values": list(suspicious_ports)[:50],  # Limit
                    }],
                    "matchActions": [{"action": "Sigkill"}],
                }],
            })

        return policy

    def save_policies(self, output_dir: str):
        """Save generated policies to files."""
        os.makedirs(output_dir, exist_ok=True)

        network_policy = self.generate_network_policy()
        with open(os.path.join(output_dir, "qualys-network-blocklist.yaml"), "w") as f:
            yaml.dump(network_policy, f, default_flow_style=False, sort_keys=False)

        tracing_policy = self.generate_tracing_policy()
        with open(os.path.join(output_dir, "qualys-tracing-blocklist.yaml"), "w") as f:
            yaml.dump(tracing_policy, f, default_flow_style=False, sort_keys=False)

        # Save raw IOCs for reference
        with open(os.path.join(output_dir, "iocs.json"), "w") as f:
            json.dump({k: list(v) for k, v in self.iocs.items()}, f, indent=2)

        return {
            "network_policy": os.path.join(output_dir, "qualys-network-blocklist.yaml"),
            "tracing_policy": os.path.join(output_dir, "qualys-tracing-blocklist.yaml"),
            "iocs_file": os.path.join(output_dir, "iocs.json"),
        }


def main():
    """CLI for threat intel feed management."""
    import argparse

    parser = argparse.ArgumentParser(description="Threat Intel Feed Manager")
    parser.add_argument("--output", "-o", default="./threat-intel-policies",
                        help="Output directory")
    parser.add_argument("--abuseipdb-key", help="AbuseIPDB API key")
    parser.add_argument("--otx-key", help="AlienVault OTX API key")

    args = parser.parse_args()

    manager = ThreatIntelManager()

    # Add open feeds (no API key required)
    manager.add_open_feeds()

    # Add API-based feeds if keys provided
    if args.abuseipdb_key:
        manager.add_feed(AbuseIPDBFeed(args.abuseipdb_key))
    if args.otx_key:
        manager.add_feed(AlienVaultOTXFeed(args.otx_key))

    print("Fetching threat intelligence feeds...")
    stats = manager.refresh_all()

    print("\nFeed statistics:")
    for feed_name, count in stats.items():
        print(f"  {feed_name}: {count} IOCs")

    print(f"\nTotal unique IOCs:")
    for ioc_type, iocs in manager.iocs.items():
        if iocs:
            print(f"  {ioc_type}: {len(iocs)}")

    print("\nGenerating policies...")
    files = manager.save_policies(args.output)

    print(f"\nPolicies saved to: {args.output}")
    for name, path in files.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()
