"""
Wazuh / OSSEC Rule Evaluator & Alert Dispatcher
Parses XML rules and evaluates incoming FIM events against security rules:
- MITRE ATT&CK mapping
- Severity levels (1 to 16)
- Compliance tags (PCI-DSS, GDPR, HIPAA, NIST)
- Standard Wazuh JSON alert formatting
"""

import re
import os
import time
import datetime
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional

class WazuhRule:
    def __init__(self, rule_id: int, level: int, description: str, match_regex: str = "",
                 mitre_ids: List[str] = None, groups: List[str] = None, options: str = ""):
        self.id = rule_id
        self.level = level
        self.description = description
        self.match_regex = match_regex
        self.mitre_ids = mitre_ids or []
        self.groups = groups or []
        self.options = options

    def matches(self, event: Dict[str, Any]) -> bool:
        path = event.get("path", "").replace("\\", "/")
        if not self.match_regex:
            return False
        if re.search(self.match_regex, path, re.IGNORECASE):
            return True
        return False


class RuleEvaluator:
    """Evaluates FIM events against Wazuh rules."""

    def __init__(self, xml_path: Optional[str] = None):
        self.rules: List[WazuhRule] = []
        self.recent_events_window: List[float] = []
        if xml_path and os.path.exists(xml_path):
            self.load_from_xml(xml_path)
        else:
            self._load_default_rules()

    def _load_default_rules(self):
        """Default rules aligned with configs/manager/local_rules.xml"""
        self.rules = [
            WazuhRule(
                rule_id=100010,
                level=10,
                description="FIM Alert: Critical system identity or privilege file modified",
                match_regex=r"(passwd|shadow|sudoers|group)$",
                mitre_ids=["T1098", "T1078"],
                groups=["syscheck", "pci_dss_10.5.5", "gdpr_IV_35.7.d"]
            ),
            WazuhRule(
                rule_id=100011,
                level=12,
                description="FIM Critical: Potential Web Shell / executable script uploaded to web server root",
                match_regex=r"(www|html|web_root|public_html).*?\.(php|phtml|php5|py|pl|sh|cgi|jsp|asp|aspx)$",
                mitre_ids=["T1505.003", "T1105"],
                groups=["syscheck", "webshell", "malware"]
            ),
            WazuhRule(
                rule_id=100012,
                level=10,
                description="FIM Alert: SSH authorized_keys file modified or created - Backdoor Indicator",
                match_regex=r"(\.ssh/authorized_keys|id_rsa\.pub)$",
                mitre_ids=["T1098.004"],
                groups=["syscheck", "persistence"]
            ),
            WazuhRule(
                rule_id=100013,
                level=12,
                description="FIM Alert: System core binary modified or replaced - Potential Rootkit",
                match_regex=r"/(bin|sbin|usr/bin|usr/sbin)/",
                mitre_ids=["T1036.005", "T1565.001"],
                groups=["syscheck", "rootkit"]
            ),
            WazuhRule(
                rule_id=100014,
                level=9,
                description="FIM Alert: Cron scheduling configuration modified - Persistence Mechanism",
                match_regex=r"(cron|crontab)",
                mitre_ids=["T1053.003"],
                groups=["syscheck", "persistence"]
            ),
            WazuhRule(
                rule_id=100015,
                level=14,
                description="FIM Critical: Decoy canary tripwire file modified or deleted - Ransomware Indicator!",
                match_regex=r"(canaries|canary|tripwire)",
                mitre_ids=["T1486", "T1485"],
                groups=["syscheck", "ransomware", "honeypot"]
            ),
            WazuhRule(
                rule_id=100018,
                level=8,
                description="FIM Warning: Network configuration modified - Potential DNS/Traffic Redirection",
                match_regex=r"(hosts|resolv\.conf|netplan)",
                mitre_ids=["T1565.001"],
                groups=["syscheck", "network_tampering"]
            )
        ]

    def load_from_xml(self, xml_path: str):
        """Parse local_rules.xml file directly."""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for rule_elem in root.findall(".//rule"):
                rule_id = int(rule_elem.get("id", "0"))
                level = int(rule_elem.get("level", "5"))
                desc = rule_elem.findtext("description", "").strip()
                match = rule_elem.findtext("match", "").strip()
                mitre_ids = [m.text for m in rule_elem.findall(".//mitre/id")]
                group_text = rule_elem.findtext("group", "")
                groups = [g.strip() for g in group_text.split(",") if g.strip()]

                # Normalize web shell regex for demo
                if rule_id == 100011:
                    match = r"(www|html|web_root|public_html).*?\.(php|phtml|php5|py|pl|sh|cgi|jsp|asp|aspx)$"

                if rule_id and desc:
                    self.rules.append(WazuhRule(
                        rule_id=rule_id,
                        level=level,
                        description=desc,
                        match_regex=match,
                        mitre_ids=mitre_ids,
                        groups=groups
                    ))
        except Exception:
            self._load_default_rules()

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluate an event against loaded rules and return a Wazuh-formatted alert."""
        matched_rule = None
        for rule in self.rules:
            if rule.matches(event):
                matched_rule = rule
                break

        # Fallback rule if no specific rule matched but file was changed
        if not matched_rule:
            matched_rule = WazuhRule(
                rule_id=550,
                level=7 if event["event_type"] == "FILE_MODIFIED" else 5,
                description=f"Integrity checksum changed for monitored file: {os.path.basename(event.get('path', ''))}",
                mitre_ids=["T1565.001"],
                groups=["syscheck"]
            )

        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        alert = {
            "timestamp": now_str,
            "rule": {
                "id": str(matched_rule.id),
                "level": matched_rule.level,
                "description": matched_rule.description,
                "groups": matched_rule.groups,
                "mitre": {
                    "id": matched_rule.mitre_ids,
                    "tactic": ["Defense Evasion", "Persistence"] if "T1098" in matched_rule.mitre_ids else ["Impact"]
                }
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab-endpoint",
                "ip": "192.168.10.50"
            },
            "manager": {
                "name": "wazuh.security-lab.local"
            },
            "syscheck": {
                "path": event["path"],
                "event": event["event_type"].lower(),
                "size_before": event.get("size_before"),
                "size_after": event.get("size_after", event.get("size")),
                "sha256_before": event.get("sha256_before"),
                "sha256_after": event.get("sha256_after", event.get("sha256")),
                "md5_before": event.get("md5_before"),
                "md5_after": event.get("md5_after", event.get("md5")),
                "diff": event.get("diff")
            },
            "location": "syscheck"
        }
        return alert
