"""Qualys API client for fetching threat data."""
import requests
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from config import QualysConfig


@dataclass
class ThreatIndicator:
    """Represents a threat indicator from Qualys."""
    qid: str
    title: str
    severity: int
    category: str
    cve_ids: List[str]
    mitre_techniques: List[str]
    solution: str


@dataclass
class RuntimeRule:
    """Represents a CRS runtime rule from Qualys."""
    rule_id: str
    rule_type: str  # syscall, file, network
    syscall: Optional[str]
    file_path: Optional[str]
    network_port: Optional[int]
    action: str
    severity: str


class QualysClient:
    """Client for Qualys API interactions."""

    def __init__(self, config: QualysConfig):
        self.config = config
        self.session = requests.Session()
        self.session.auth = (config.username, config.password)
        self.session.headers.update({
            "X-Requested-With": "Python",
            "Content-Type": "application/xml",
        })

    def get_knowledgebase(self,
                         severity_min: int = 3,
                         published_after: Optional[str] = None) -> List[ThreatIndicator]:
        """
        Fetch vulnerability data from Qualys KnowledgeBase.

        Args:
            severity_min: Minimum severity level (1-5)
            published_after: Filter by publication date (YYYY-MM-DD)

        Returns:
            List of ThreatIndicator objects
        """
        url = f"{self.config.api_url}/api/2.0/fo/knowledge_base/vuln/"

        params = {
            "action": "list",
            "details": "All",
            "show_qid_change_log": "1",
        }

        if severity_min:
            params["severity"] = f"{severity_min}-5"
        if published_after:
            params["published_after"] = published_after

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return self._parse_knowledgebase_response(response.text)
        except requests.RequestException as e:
            print(f"Error fetching KnowledgeBase: {e}")
            return []

    def get_threat_protection_data(self) -> List[Dict[str, Any]]:
        """
        Fetch Real-Time Threat Indicators (RTIs) from Qualys Threat Protection.

        Returns:
            List of threat indicators with exploit/malware associations
        """
        url = f"{self.config.api_url}/api/2.0/fo/knowledge_base/vuln/"

        params = {
            "action": "list",
            "details": "All",
            "show_rti": "1",  # Include Real-Time Threat Indicators
        }

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return self._parse_threat_data(response.text)
        except requests.RequestException as e:
            print(f"Error fetching Threat Protection data: {e}")
            return []

    def get_container_runtime_policies(self) -> List[RuntimeRule]:
        """
        Fetch CRS runtime policies from Qualys Container Security.

        Returns:
            List of RuntimeRule objects
        """
        url = f"{self.config.api_url}/csapi/v1.3/crs/policies"

        try:
            response = self.session.get(url)
            response.raise_for_status()
            return self._parse_runtime_policies(response.json())
        except requests.RequestException as e:
            print(f"Error fetching CRS policies: {e}")
            return []

    def get_behavioral_baseline(self, container_id: str) -> Dict[str, Any]:
        """
        Fetch behavioral baseline for a container from CRS.

        Args:
            container_id: Container identifier

        Returns:
            Dictionary containing behavioral baseline data
        """
        url = f"{self.config.api_url}/csapi/v1.3/crs/baselines/{container_id}"

        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching baseline: {e}")
            return {}

    def _parse_knowledgebase_response(self, xml_data: str) -> List[ThreatIndicator]:
        """Parse XML response from KnowledgeBase API."""
        indicators = []
        try:
            root = ET.fromstring(xml_data)
            for vuln in root.findall(".//VULN"):
                qid = vuln.findtext("QID", "")
                title = vuln.findtext("TITLE", "")
                severity = int(vuln.findtext("SEVERITY", "1"))
                category = vuln.findtext("CATEGORY", "")

                cve_ids = []
                cve_list = vuln.find("CVE_LIST")
                if cve_list is not None:
                    cve_ids = [cve.findtext("ID", "") for cve in cve_list.findall("CVE")]

                mitre = []
                mitre_info = vuln.find("MITRE_INFO")
                if mitre_info is not None:
                    for technique in mitre_info.findall(".//TECHNIQUE"):
                        tech_id = technique.findtext("ID", "")
                        if tech_id:
                            mitre.append(tech_id)

                solution = vuln.findtext("SOLUTION", "")

                indicators.append(ThreatIndicator(
                    qid=qid,
                    title=title,
                    severity=severity,
                    category=category,
                    cve_ids=cve_ids,
                    mitre_techniques=mitre,
                    solution=solution,
                ))
        except ET.ParseError as e:
            print(f"Error parsing KnowledgeBase XML: {e}")

        return indicators

    def _parse_threat_data(self, xml_data: str) -> List[Dict[str, Any]]:
        """Parse threat data including RTIs."""
        threats = []
        try:
            root = ET.fromstring(xml_data)
            for vuln in root.findall(".//VULN"):
                threat = {
                    "qid": vuln.findtext("QID", ""),
                    "title": vuln.findtext("TITLE", ""),
                    "severity": int(vuln.findtext("SEVERITY", "1")),
                    "exploitable": False,
                    "malware_associated": False,
                    "actively_exploited": False,
                }

                rti = vuln.find("THREAT_INTELLIGENCE")
                if rti is not None:
                    threat["exploitable"] = rti.findtext("EXPLOIT_AVAILABLE", "0") == "1"
                    threat["malware_associated"] = rti.findtext("MALWARE", "0") == "1"
                    threat["actively_exploited"] = rti.findtext("ACTIVE_ATTACKS", "0") == "1"

                threats.append(threat)
        except ET.ParseError as e:
            print(f"Error parsing threat data XML: {e}")

        return threats

    def _parse_runtime_policies(self, json_data: Dict) -> List[RuntimeRule]:
        """Parse CRS runtime policies from JSON response."""
        rules = []
        for policy in json_data.get("policies", []):
            for rule in policy.get("rules", []):
                rules.append(RuntimeRule(
                    rule_id=rule.get("id", ""),
                    rule_type=rule.get("type", ""),
                    syscall=rule.get("syscall"),
                    file_path=rule.get("filePath"),
                    network_port=rule.get("port"),
                    action=rule.get("action", "audit"),
                    severity=rule.get("severity", "medium"),
                ))
        return rules
