"""
ThreatScope V2 — Correlation Rules Engine
Author: 0xSABRY

Multi-stage attack correlation with time-window analysis,
kill chain detection, and weighted scoring.
"""

from collections import defaultdict
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta


# ============================================================
# Correlation Rule Definitions
# ============================================================
CORRELATION_RULES = [
    # Kill Chain Correlations
    {
        "id": "CORR-001",
        "name": "Full Kill Chain Detected",
        "requires": ["credential_dumping", "lateral_movement", "data_exfiltration"],
        "severity": "critical",
        "score_boost": 30,
        "mitre_chain": ["TA0006", "TA0008", "TA0010"],
        "desc": "Credential theft → lateral movement → data exfiltration — full attack kill chain detected",
    },
    {
        "id": "CORR-002",
        "name": "Credential Compromise Chain",
        "requires": ["brute_force", "privilege_escalation"],
        "severity": "critical",
        "score_boost": 20,
        "mitre_chain": ["TA0006", "TA0004"],
        "desc": "Brute-force followed by privilege escalation — likely credential compromise",
    },
    {
        "id": "CORR-003",
        "name": "Ransomware Deployment Chain",
        "requires": ["lateral_movement", "av_tamper", "ransomware"],
        "severity": "critical",
        "score_boost": 25,
        "mitre_chain": ["TA0008", "TA0005", "TA0040"],
        "desc": "Lateral movement → AV disabling → ransomware — coordinated ransomware attack",
    },
    {
        "id": "CORR-004",
        "name": "Active C2 with Exfiltration",
        "requires": ["command_and_control", "data_exfiltration"],
        "severity": "critical",
        "score_boost": 20,
        "mitre_chain": ["TA0011", "TA0010"],
        "desc": "Active C2 channel with data exfiltration — ongoing data breach",
    },
    {
        "id": "CORR-005",
        "name": "Persistence + Defense Evasion",
        "requires": ["persistence", "log_tampering"],
        "severity": "critical",
        "score_boost": 15,
        "mitre_chain": ["TA0003", "TA0005"],
        "desc": "Persistence mechanism with log clearing — adversary covering tracks",
    },
    {
        "id": "CORR-006",
        "name": "Insider Threat Indicators",
        "requires": ["off_hours_access", "bulk_download"],
        "severity": "high",
        "score_boost": 15,
        "mitre_chain": ["TA0001", "TA0009"],
        "desc": "Off-hours access with bulk downloads — potential malicious insider",
    },
    {
        "id": "CORR-007",
        "name": "AD Compromise Chain",
        "requires": ["ad_recon", "kerberoasting", "golden_silver_ticket"],
        "severity": "critical",
        "score_boost": 30,
        "mitre_chain": ["TA0007", "TA0006", "TA0006"],
        "desc": "AD recon → Kerberoasting → Golden Ticket — full Active Directory compromise",
    },
    {
        "id": "CORR-008",
        "name": "Supply Chain + Persistence",
        "requires": ["dependency_confusion", "persistence"],
        "severity": "critical",
        "score_boost": 20,
        "mitre_chain": ["TA0001", "TA0003"],
        "desc": "Supply chain compromise with persistence — advanced persistent threat",
    },
    {
        "id": "CORR-009",
        "name": "Web Attack to Shell",
        "requires": ["sql_injection", "reverse_shell"],
        "severity": "critical",
        "score_boost": 20,
        "mitre_chain": ["TA0001", "TA0002"],
        "desc": "SQL injection leading to reverse shell — web app fully compromised",
    },
    {
        "id": "CORR-010",
        "name": "Phishing to Credential Dump",
        "requires": ["phishing_url", "credential_dumping"],
        "severity": "critical",
        "score_boost": 20,
        "mitre_chain": ["TA0001", "TA0006"],
        "desc": "Phishing → credential dumping — social engineering attack chain",
    },
    {
        "id": "CORR-011",
        "name": "API Attack Chain",
        "requires": ["jwt_abuse", "broken_auth_api"],
        "severity": "critical",
        "score_boost": 20,
        "mitre_chain": ["TA0001", "TA0006"],
        "desc": "JWT abuse with BOLA — API fully compromised",
    },
    {
        "id": "CORR-012",
        "name": "AI System Compromise",
        "requires": ["prompt_injection", "data_extraction_llm"],
        "severity": "critical",
        "score_boost": 25,
        "mitre_chain": ["TA0001", "TA0009"],
        "desc": "Prompt injection → training data extraction — AI system compromised",
    },
    {
        "id": "CORR-013",
        "name": "MFA Bypass + Lateral Movement",
        "requires": ["mfa_fatigue", "lateral_movement"],
        "severity": "critical",
        "score_boost": 25,
        "mitre_chain": ["TA0006", "TA0008"],
        "desc": "MFA bypass via fatigue → lateral movement — identity compromise",
    },
    {
        "id": "CORR-014",
        "name": "Crypto Theft Chain",
        "requires": ["wallet_theft", "crypto_clipper"],
        "severity": "critical",
        "score_boost": 25,
        "mitre_chain": ["TA0009", "TA0040"],
        "desc": "Wallet theft + clipboard hijacking — cryptocurrency attack chain",
    },
    {
        "id": "CORR-015",
        "name": "Network MitM + Credential Theft",
        "requires": ["arp_poisoning", "credential_dumping"],
        "severity": "critical",
        "score_boost": 20,
        "mitre_chain": ["TA0006", "TA0006"],
        "desc": "ARP poisoning → credential capture — network-level MitM attack",
    },
    # New V2 correlations
    {
        "id": "CORR-016",
        "name": "Cloud Account Takeover",
        "requires": ["cloud_credential_theft", "cloud_resource_creation"],
        "severity": "critical",
        "score_boost": 25,
        "mitre_chain": ["TA0006", "TA0042"],
        "desc": "Cloud credential theft → unauthorized resource creation — cloud account takeover",
    },
    {
        "id": "CORR-017",
        "name": "Container Escape Chain",
        "requires": ["container_escape", "privilege_escalation"],
        "severity": "critical",
        "score_boost": 25,
        "mitre_chain": ["TA0004", "TA0004"],
        "desc": "Container escape → host privilege escalation — infrastructure compromise",
    },
    {
        "id": "CORR-018",
        "name": "Initial Access to Persistence",
        "requires": ["exploit_public_app", "persistence"],
        "severity": "high",
        "score_boost": 20,
        "mitre_chain": ["TA0001", "TA0003"],
        "desc": "Exploitation followed by persistence creation — attacker establishing foothold",
    },
    {
        "id": "CORR-019",
        "name": "Discovery to Exfiltration",
        "requires": ["network_discovery", "data_exfiltration"],
        "severity": "high",
        "score_boost": 15,
        "mitre_chain": ["TA0007", "TA0010"],
        "desc": "Network discovery followed by exfiltration — targeted data theft",
    },
    {
        "id": "CORR-020",
        "name": "Living Off The Land Chain",
        "requires": ["powershell_abuse", "wmi_abuse", "scheduled_task"],
        "severity": "high",
        "score_boost": 20,
        "mitre_chain": ["TA0002", "TA0002", "TA0003"],
        "desc": "PowerShell → WMI → Scheduled Task — living off the land attack chain",
    },
]


class CorrelationEngine:
    """
    Correlates findings across multiple detection categories to identify
    multi-stage attacks and kill chains.
    """

    def __init__(self, custom_rules: Optional[List[dict]] = None):
        """
        Initialize the correlation engine.

        Args:
            custom_rules: Optional list of custom correlation rules.
        """
        self.rules = CORRELATION_RULES.copy()
        if custom_rules:
            self.rules.extend(custom_rules)
        self.triggered_correlations: List[dict] = []

    def correlate(self, findings: Dict[str, list]) -> List[dict]:
        """
        Run correlation analysis against all findings.

        Args:
            findings: Dictionary mapping category names to lists of individual findings.

        Returns:
            List of triggered correlation results with metadata.
        """
        self.triggered_correlations = []
        detected_categories = set(findings.keys())

        for rule in self.rules:
            required = set(rule["requires"])
            if required.issubset(detected_categories):
                correlation_result = {
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "score_boost": rule["score_boost"],
                    "description": rule["desc"],
                    "matched_categories": list(required),
                    "mitre_chain": rule.get("mitre_chain", []),
                    "evidence_count": sum(
                        len(findings[cat]) for cat in required if cat in findings
                    ),
                    "evidence_samples": self._get_evidence_samples(findings, required),
                }
                self.triggered_correlations.append(correlation_result)

        # Sort by severity and score
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.triggered_correlations.sort(
            key=lambda x: (severity_order.get(x["severity"], 4), -x["score_boost"])
        )

        return self.triggered_correlations

    def _get_evidence_samples(
        self, findings: Dict[str, list], categories: set, max_samples: int = 3
    ) -> Dict[str, list]:
        """
        Get sample evidence for each matched category.

        Args:
            findings: All findings.
            categories: Categories that matched.
            max_samples: Maximum samples per category.

        Returns:
            Dictionary of category -> sample findings.
        """
        samples = {}
        for cat in categories:
            if cat in findings:
                samples[cat] = findings[cat][:max_samples]
        return samples

    def get_score_boost(self) -> int:
        """
        Calculate total threat score boost from correlations.

        Returns:
            Total score boost from all triggered correlations.
        """
        return sum(c["score_boost"] for c in self.triggered_correlations)

    def get_kill_chain_coverage(self) -> Dict[str, bool]:
        """
        Analyze kill chain coverage from correlations.

        Returns:
            Dictionary showing which kill chain phases were detected.
        """
        kill_chain_phases = {
            "Reconnaissance": False,
            "Initial Access": False,
            "Execution": False,
            "Persistence": False,
            "Privilege Escalation": False,
            "Defense Evasion": False,
            "Credential Access": False,
            "Discovery": False,
            "Lateral Movement": False,
            "Collection": False,
            "Exfiltration": False,
            "Command & Control": False,
            "Impact": False,
        }

        tactic_to_phase = {
            "TA0043": "Reconnaissance",
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0010": "Exfiltration",
            "TA0011": "Command & Control",
            "TA0040": "Impact",
        }

        for corr in self.triggered_correlations:
            for tactic in corr.get("mitre_chain", []):
                phase = tactic_to_phase.get(tactic)
                if phase:
                    kill_chain_phases[phase] = True

        return kill_chain_phases

    def get_summary(self) -> dict:
        """Get a summary of correlation results."""
        return {
            "total_correlations": len(self.triggered_correlations),
            "critical": len([c for c in self.triggered_correlations if c["severity"] == "critical"]),
            "high": len([c for c in self.triggered_correlations if c["severity"] == "high"]),
            "total_score_boost": self.get_score_boost(),
            "kill_chain": self.get_kill_chain_coverage(),
            "correlations": self.triggered_correlations,
        }
