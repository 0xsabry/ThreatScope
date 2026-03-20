"""
ThreatScope V2 — Main Analyzer Orchestrator
Author: 0xSABRY

Central analysis engine that coordinates all detection modules:
Sigma rules, regex patterns, YARA scanning, behavioral chains,
correlation, IOC extraction, and threat scoring.
"""

import re
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Any

from core.sigma_engine import SigmaEngine
from core.yara_engine import YaraEngine
from core.ioc_extractor import IOCExtractor
from core.correlation import CorrelationEngine
from core.behavioral_chain import BehavioralChainEngine
from core.false_positive import FalsePositiveSuppressor
from parsers.log_parsers import get_parser, compute_file_hashes, TextLogParser

logger = logging.getLogger("threatscope.analyzer")


# ============================================================
# Built-in Detection Patterns (115+ regex rules from v3)
# ============================================================
BUILTIN_PATTERNS = {
    # Brute Force & Authentication
    "brute_force": {
        "patterns": [r"(?:failed|invalid)\s+(?:login|password|auth)", r"authentication\s+fail",
                     r"login\s+attempt.*fail", r"access\s+denied.*(?:user|login)", r"4625.*Audit\s+Failure"],
        "severity": "high", "weight": 20, "category": "Brute Force",
        "desc": "Multiple failed authentication attempts detected", "mitre": "T1110",
    },
    "credential_dumping": {
        "patterns": [r"mimikatz", r"sekurlsa", r"lsass\.exe.*access", r"hashdump",
                     r"gsecdump", r"wce\.exe", r"procdump.*lsass", r"comsvcs\.dll.*MiniDump"],
        "severity": "critical", "weight": 40, "category": "Credential Dumping",
        "desc": "Credential dumping tool or technique detected", "mitre": "T1003",
    },
    "privilege_escalation": {
        "patterns": [r"privilege\s+escalat", r"UAC\s+bypass", r"admin.*token",
                     r"sudo\s+.*NOPASSWD", r"4672.*Special\s+privileges", r"getsystem",
                     r"SeDebugPrivilege", r"JuicyPotato", r"PrintSpoofer"],
        "severity": "critical", "weight": 35, "category": "Privilege Escalation",
        "desc": "Privilege escalation attempt detected", "mitre": "T1068",
    },
    "lateral_movement": {
        "patterns": [r"psexec", r"wmiexec", r"smbexec", r"atexec", r"dcomexec",
                     r"evil-winrm", r"Enter-PSSession", r"Invoke-Command.*-Computer",
                     r"net\s+use.*\\\\", r"5140.*Network\s+Share"],
        "severity": "critical", "weight": 35, "category": "Lateral Movement",
        "desc": "Lateral movement technique detected", "mitre": "T1021",
    },
    "data_exfiltration": {
        "patterns": [r"exfiltrat", r"rclone\s+copy", r"mega(?:cmd|sync)",
                     r"curl.*-(?:T|d\s+@)", r"scp\s+.*@.*:", r"dns.*tunnel",
                     r"base64.*>.*\.txt", r"7z\s+a.*-p"],
        "severity": "critical", "weight": 35, "category": "Data Exfiltration",
        "desc": "Data exfiltration technique detected", "mitre": "T1041",
    },
    "persistence": {
        "patterns": [r"schtasks\s*/create", r"sc\s+create", r"reg\s+add.*Run",
                     r"crontab\s+-e", r"systemctl\s+enable", r"at\s+\d+:\d+",
                     r"HKLM\\.*\\Run", r"New-Service", r"Register-ScheduledTask"],
        "severity": "high", "weight": 25, "category": "Persistence",
        "desc": "Persistence mechanism creation detected", "mitre": "T1053",
    },
    "command_and_control": {
        "patterns": [r"beacon", r"cobalt\s*strike", r"meterpreter", r"empire",
                     r"reverse.*shell", r"bind.*shell", r"nc\s+-.*-e",
                     r"C2\s+channel", r"sliver", r"covenant"],
        "severity": "critical", "weight": 40, "category": "Command & Control",
        "desc": "Command & control activity detected", "mitre": "T1071",
    },
    "ransomware": {
        "patterns": [r"ransom", r"encrypt.*(?:files|documents)", r"\.locked$",
                     r"bitcoin.*wallet", r"your\s+files.*encrypted",
                     r"vssadmin.*delete.*shadows", r"wbadmin\s+delete",
                     r"bcdedit.*recoveryenabled.*no"],
        "severity": "critical", "weight": 40, "category": "Ransomware",
        "desc": "Ransomware indicators detected", "mitre": "T1486",
    },
    "log_tampering": {
        "patterns": [r"wevtutil\s+cl", r"Clear-EventLog", r"1102.*Log\s+Clear",
                     r"auditpol.*disable", r"rm\s+-rf\s+/var/log",
                     r"history\s*-c", r"shred\s+.*\.log"],
        "severity": "critical", "weight": 35, "category": "Log Tampering",
        "desc": "Log tampering or anti-forensics detected", "mitre": "T1070",
    },
    "reverse_shell": {
        "patterns": [r"bash\s+-i\s+>&\s+/dev/tcp", r"nc\s+.*-e\s+/bin/(?:ba)?sh",
                     r"python.*socket.*connect.*exec", r"php\s+-r.*fsockopen",
                     r"ruby.*TCPSocket.*exec", r"powershell.*Net\.Sockets"],
        "severity": "critical", "weight": 40, "category": "Reverse Shell",
        "desc": "Reverse shell technique detected", "mitre": "T1059",
    },
    "sql_injection": {
        "patterns": [r"(?:UNION|SELECT).*(?:FROM|WHERE).*(?:--|;)", r"OR\s+1\s*=\s*1",
                     r"(?:DROP|ALTER)\s+TABLE", r"WAITFOR\s+DELAY",
                     r"xp_cmdshell", r"load_file\s*\(", r"INTO\s+OUTFILE"],
        "severity": "high", "weight": 25, "category": "SQL Injection",
        "desc": "SQL injection attempt detected", "mitre": "T1190",
    },
    "powershell_abuse": {
        "patterns": [r"(?:-enc|-EncodedCommand)\s+[A-Za-z0-9+/=]{20,}",
                     r"Invoke-Expression", r"IEX\s*\(", r"Invoke-Mimikatz",
                     r"Download(?:String|File)", r"Net\.WebClient",
                     r"Set-MpPreference.*-DisableRealtimeMonitoring"],
        "severity": "high", "weight": 25, "category": "PowerShell Abuse",
        "desc": "Suspicious PowerShell activity detected", "mitre": "T1059.001",
    },
    "av_tamper": {
        "patterns": [r"Set-MpPreference.*Disable", r"net\s+stop.*(?:defender|antivirus|mcafee|norton)",
                     r"sc\s+(?:stop|delete).*(?:Security|Windefend)",
                     r"kill.*(?:avp|avgnt|mbam|norton|defender)"],
        "severity": "critical", "weight": 35, "category": "AV Tampering",
        "desc": "Security tool tampering detected", "mitre": "T1562.001",
    },
    "kerberoasting": {
        "patterns": [r"kerberoast", r"Invoke-Kerberoast", r"GetUserSPNs",
                     r"4769.*(?:0x17|Encryption\s+Type:.*0x17)", r"Rubeus.*kerberoast"],
        "severity": "critical", "weight": 35, "category": "Kerberoasting",
        "desc": "Kerberoasting attack detected", "mitre": "T1558.003",
    },
    "golden_silver_ticket": {
        "patterns": [r"golden.*ticket", r"silver.*ticket", r"Invoke-(?:Golden|Silver)Ticket",
                     r"mimikatz.*kerberos::golden", r"ticketer\.py"],
        "severity": "critical", "weight": 40, "category": "Golden/Silver Ticket",
        "desc": "Kerberos ticket forging detected", "mitre": "T1558.001",
    },
    "ad_recon": {
        "patterns": [r"BloodHound", r"SharpHound", r"Get-(?:Domain|Forest|Net)",
                     r"ldapsearch", r"enum4linux", r"windapsearch",
                     r"PowerView", r"ADRecon"],
        "severity": "high", "weight": 25, "category": "AD Reconnaissance",
        "desc": "Active Directory reconnaissance detected", "mitre": "T1087.002",
    },
    "phishing_url": {
        "patterns": [r"(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co)/\S+",
                     r"login.*\.(?:xyz|tk|ml|ga|cf|pw)/",
                     r"(?:verify|confirm|secure).*account.*(?:click|link)"],
        "severity": "medium", "weight": 15, "category": "Phishing",
        "desc": "Phishing URL or social engineering indicators", "mitre": "T1566",
    },
    "network_discovery": {
        "patterns": [r"nmap\s+", r"masscan\s+", r"net\s+view", r"arp\s+-a",
                     r"netstat\s+-", r"ipconfig\s+/all", r"ifconfig"],
        "severity": "medium", "weight": 15, "category": "Network Discovery",
        "desc": "Network discovery commands detected", "mitre": "T1046",
    },
    "wmi_abuse": {
        "patterns": [r"wmic\s+", r"Get-WmiObject", r"Invoke-WmiMethod",
                     r"ManagementObject.*Win32_", r"wmic\s+process\s+call"],
        "severity": "medium", "weight": 15, "category": "WMI Abuse",
        "desc": "WMI abuse for execution or recon", "mitre": "T1047",
    },
    "scheduled_task": {
        "patterns": [r"schtasks\s*/create", r"Register-ScheduledTask",
                     r"crontab", r"at\s+\d+:\d+\s+"],
        "severity": "medium", "weight": 15, "category": "Scheduled Task",
        "desc": "Scheduled task creation detected", "mitre": "T1053.005",
    },
    "off_hours_access": {
        "patterns": [r"(?:0[0-4]|2[2-3]):\d{2}:\d{2}.*(?:logon|login|auth.*success)"],
        "severity": "medium", "weight": 10, "category": "Off-Hours Access",
        "desc": "Logon activity during unusual hours", "mitre": "T1078",
    },
    "bulk_download": {
        "patterns": [r"(?:wget|curl|certutil).*-(?:O|o|urlcache)",
                     r"bitsadmin.*transfer", r"large.*download", r"bulk.*export"],
        "severity": "medium", "weight": 15, "category": "Bulk Download",
        "desc": "Bulk file download or staging activity", "mitre": "T1105",
    },
    "container_escape": {
        "patterns": [r"docker\.sock", r"mount.*nsenter", r"docker.*--privileged",
                     r"kubernetes.*exec", r"kubectl.*exec"],
        "severity": "critical", "weight": 35, "category": "Container Escape",
        "desc": "Container escape attempt detected", "mitre": "T1611",
    },
    "arp_poisoning": {
        "patterns": [r"arp.*(?:spoof|poison)", r"ettercap", r"bettercap.*arp",
                     r"arpwatch.*changed", r"duplicate.*IP.*address"],
        "severity": "high", "weight": 25, "category": "ARP Poisoning",
        "desc": "ARP spoofing/poisoning detected", "mitre": "T1557.002",
    },
    "mfa_fatigue": {
        "patterns": [r"multiple.*push.*notification", r"MFA.*(?:denied|timeout).*repeated",
                     r"2FA.*bomb", r"authentication.*push.*spam"],
        "severity": "high", "weight": 25, "category": "MFA Fatigue",
        "desc": "MFA fatigue/push bombing attack detected", "mitre": "T1621",
    },
    "jwt_abuse": {
        "patterns": [r"JWT.*(?:none|alg.*none)", r"(?:eyJ|jwt).*(?:tamper|forge|modify)",
                     r"token.*(?:replay|reuse)"],
        "severity": "high", "weight": 25, "category": "JWT Abuse",
        "desc": "JWT token abuse detected", "mitre": "T1528",
    },
    "prompt_injection": {
        "patterns": [r"ignore\s+(?:previous|all)\s+instructions",
                     r"(?:system|admin)\s+prompt.*override",
                     r"jailbreak.*(?:DAN|bypass)"],
        "severity": "medium", "weight": 15, "category": "Prompt Injection",
        "desc": "AI prompt injection attempt detected", "mitre": "T1059",
    },
}


class LogAnalyzer:
    """
    Central analysis orchestrator that coordinates all detection modules.
    
    Supports multiple log formats, runs Sigma rules, regex patterns,
    YARA scans, and behavioral chains, then produces a unified
    threat assessment with scoring and MITRE ATT&CK mapping.
    """

    def __init__(self, filepath: str = None):
        """
        Initialize the analyzer.

        Args:
            filepath: Path to the log file to analyze.
        """
        self.filepath = Path(filepath) if filepath else None
        self.events: List[dict] = []
        self.findings: Dict[str, List[dict]] = defaultdict(list)
        self.timeline: List[dict] = []
        self.mitre_hits: Dict[str, int] = defaultdict(int)

        # Sub-engines
        self.sigma_engine = SigmaEngine()
        self.yara_engine = YaraEngine()
        self.ioc_extractor = IOCExtractor()
        self.correlation_engine = CorrelationEngine()
        self.behavioral_engine = BehavioralChainEngine()
        self.fp_suppressor = FalsePositiveSuppressor()

        # Counters
        self.ip_counter = Counter()
        self.user_counter = Counter()
        self.event_id_counter = Counter()

        # Metadata
        self.file_hashes = {}
        self.start_time = None
        self.end_time = None
        self.total_lines = 0
        self.sigma_rules_loaded = 0
        self.analysis_complete = False
        self.analysis_timestamp = None

    def load(self, filepath: str = None):
        """
        Load and parse log file using the appropriate parser.

        Args:
            filepath: Optional override for file path.
        """
        if filepath:
            self.filepath = Path(filepath)

        if not self.filepath or not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

        logger.info(f"Loading log file: {self.filepath}")

        # Compute file hashes
        self.file_hashes = compute_file_hashes(str(self.filepath))

        # Auto-detect parser and parse
        parser = get_parser(str(self.filepath))
        self.events = parser.parse(str(self.filepath))
        self.total_lines = len(self.events)

        # Load Sigma rules
        self.sigma_rules_loaded = self.sigma_engine.load_rules()

        # Load YARA rules
        self.yara_engine.load_rules()

        logger.info(
            f"Loaded {self.total_lines} events | "
            f"MD5: {self.file_hashes.get('md5', 'N/A')} | "
            f"Sigma rules: {self.sigma_rules_loaded} | "
            f"YARA rules: {self.yara_engine.rule_count}"
        )

    def analyze(self) -> Dict:
        """
        Run full analysis pipeline on loaded events.

        Returns:
            Complete analysis results dictionary.
        """
        if not self.events:
            logger.warning("No events loaded — nothing to analyze.")
            return self.get_results()

        logger.info(f"Analyzing {len(self.events)} events...")

        for event in self.events:
            self._analyze_event(event)

        # Run correlation analysis
        self.correlation_engine.correlate(self.findings)

        # Run behavioral chain analysis
        self.behavioral_engine.add_events_from_findings(self.findings, self.timeline)
        self.behavioral_engine.analyze()

        # Apply FP suppression
        for category in list(self.findings.keys()):
            filtered, suppressed = self.fp_suppressor.filter_findings(self.findings[category])
            self.findings[category] = filtered

        # YARA scan on the original file
        if self.filepath and self.filepath.suffix.lower() in ('.exe', '.dll', '.bin', '.dmp'):
            self.yara_engine.scan_file(str(self.filepath))

        self.analysis_complete = True
        self.analysis_timestamp = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Analysis complete: {sum(len(v) for v in self.findings.values())} findings | "
            f"{len(self.mitre_hits)} MITRE techniques | "
            f"{self.ioc_extractor.get_summary()['total_iocs']} IOCs"
        )

        return self.get_results()

    def _analyze_event(self, event: dict):
        """
        Analyze a single event against all detection rules.

        Args:
            event: Normalized event dictionary.
        """
        raw = event.get("raw", "")
        if not raw:
            return

        # Track IPs
        for ip in re.findall(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", raw):
            self.ip_counter[ip] += 1

        # Track usernames
        for user in re.findall(
            r"(?:user|username|account)[=: ]+([a-zA-Z0-9_\-\.]+)", raw, re.IGNORECASE
        ):
            self.user_counter[user] += 1

        # Track Event IDs
        eid = event.get("event_id", "")
        if eid:
            self.event_id_counter[eid] += 1

        # Track timestamps
        ts = event.get("timestamp", "")
        if ts:
            if not self.start_time:
                self.start_time = ts
            self.end_time = ts

        # IOC extraction
        self.ioc_extractor.extract_from_event(event)

        # Run builtin regex patterns
        raw_lower = raw.lower()
        for rule_id, rule in BUILTIN_PATTERNS.items():
            for pattern in rule["patterns"]:
                try:
                    if re.search(pattern, raw, re.IGNORECASE):
                        finding = {
                            "rule_id": rule_id,
                            "rule_type": "builtin",
                            "title": rule["category"],
                            "description": rule["desc"],
                            "severity": rule["severity"],
                            "weight": rule["weight"],
                            "mitre": rule.get("mitre", ""),
                            "line_number": event.get("line_number", 0),
                            "raw": raw[:500],
                            "timestamp": ts,
                            "matched_pattern": pattern,
                        }
                        self.findings[rule_id].append(finding)

                        if rule.get("mitre"):
                            self.mitre_hits[rule["mitre"]] += 1

                        self.timeline.append({
                            "timestamp": ts,
                            "category": rule_id,
                            "title": rule["category"],
                            "severity": rule["severity"],
                            "line_number": event.get("line_number", 0),
                            "raw": raw[:300],
                        })
                        break  # One match per rule per event
                except re.error:
                    continue

        # Run Sigma rules
        if self.sigma_engine.available and self.sigma_engine.rules:
            sigma_matches = self.sigma_engine.match_event(event)
            for match in sigma_matches:
                finding = {
                    "rule_id": match.get("rule_id", ""),
                    "rule_type": "sigma",
                    "title": match["title"],
                    "description": match["description"],
                    "severity": match["level"],
                    "weight": match["weight"],
                    "mitre": ", ".join(match.get("mitre_techniques", [])),
                    "line_number": event.get("line_number", 0),
                    "raw": raw[:500],
                    "timestamp": ts,
                }
                cat_key = f"sigma_{match.get('rule_id', 'unknown')}"
                self.findings[cat_key].append(finding)

                for tech in match.get("mitre_techniques", []):
                    self.mitre_hits[tech] += 1

                self.timeline.append({
                    "timestamp": ts,
                    "category": cat_key,
                    "title": f"Sigma: {match['title']}",
                    "severity": match["level"],
                    "line_number": event.get("line_number", 0),
                    "raw": raw[:300],
                })

    def calculate_threat_score(self) -> int:
        """
        Calculate overall threat score (0-100).

        Returns:
            Threat score as integer percentage.
        """
        if not self.findings:
            return 0

        base_score = 0
        for category, finding_list in self.findings.items():
            if finding_list:
                max_weight = max(f.get("weight", 10) for f in finding_list)
                count_boost = min(len(finding_list) * 2, 20)
                base_score += max_weight + count_boost

        # Correlation boost
        base_score += self.correlation_engine.get_score_boost()

        # Behavioral chain boost
        for chain in self.behavioral_engine.triggered_chains:
            base_score += int(chain.get("confidence", 0.5) * 15)

        # Normalize to 0-100
        return min(100, max(0, int(base_score * 100 / max(base_score + 50, 1))))

    def get_threat_level(self, score: int = None) -> tuple:
        """
        Determine threat level from score.

        Args:
            score: Optional pre-calculated score.

        Returns:
            Tuple of (level_name, color).
        """
        if score is None:
            score = self.calculate_threat_score()

        if score >= 80:
            return "CRITICAL", "#ff1744"
        elif score >= 60:
            return "HIGH", "#ef4444"
        elif score >= 40:
            return "MEDIUM", "#f59e0b"
        elif score >= 20:
            return "LOW", "#3b82f6"
        else:
            return "INFORMATIONAL", "#64748b"

    def get_results(self) -> dict:
        """
        Get complete analysis results.

        Returns:
            Comprehensive results dictionary.
        """
        score = self.calculate_threat_score()
        level, level_color = self.get_threat_level(score)
        total_findings = sum(len(v) for v in self.findings.values())
        ioc_summary = self.ioc_extractor.get_summary()

        # Flatten all findings for display
        all_findings = []
        for category, finding_list in self.findings.items():
            for finding in finding_list:
                finding["category_key"] = category
                all_findings.append(finding)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "").lower(), 5))

        # Sort timeline
        self.timeline.sort(key=lambda t: t.get("timestamp", ""))

        return {
            "metadata": {
                "filepath": str(self.filepath) if self.filepath else "",
                "file_hashes": self.file_hashes,
                "total_events": self.total_lines,
                "analysis_timestamp": self.analysis_timestamp,
                "time_range": {"start": self.start_time, "end": self.end_time},
                "sigma_rules_loaded": self.sigma_rules_loaded,
                "yara_rules_loaded": self.yara_engine.rule_count,
            },
            "threat_score": score,
            "threat_level": level,
            "threat_color": level_color,
            "summary": {
                "total_findings": total_findings,
                "critical": len([f for f in all_findings if f.get("severity", "").lower() == "critical"]),
                "high": len([f for f in all_findings if f.get("severity", "").lower() == "high"]),
                "medium": len([f for f in all_findings if f.get("severity", "").lower() == "medium"]),
                "low": len([f for f in all_findings if f.get("severity", "").lower() == "low"]),
                "unique_ips": len(self.ip_counter),
                "unique_users": len(self.user_counter),
                "mitre_techniques": len(self.mitre_hits),
                "total_iocs": ioc_summary["total_iocs"],
                "correlations": len(self.correlation_engine.triggered_correlations),
                "behavioral_chains": len(self.behavioral_engine.triggered_chains),
            },
            "findings": all_findings,
            "findings_by_category": {k: v for k, v in self.findings.items()},
            "timeline": self.timeline[:1000],  # Limit timeline entries
            "mitre_hits": dict(self.mitre_hits),
            "iocs": ioc_summary,
            "correlations": self.correlation_engine.get_summary(),
            "behavioral_chains": self.behavioral_engine.get_summary(),
            "top_ips": self.ip_counter.most_common(20),
            "top_users": self.user_counter.most_common(20),
            "top_event_ids": self.event_id_counter.most_common(20),
            "fp_stats": self.fp_suppressor.get_stats(),
            "yara": self.yara_engine.get_summary(),
            "sigma_stats": self.sigma_engine.get_stats() if self.sigma_engine.available else {},
        }

    def generate_report(self) -> str:
        """Generate a text-based analysis report."""
        results = self.get_results()
        score = results["threat_score"]
        level = results["threat_level"]

        lines = [
            "=" * 70,
            f"  0xSABRY ThreatScope V2 — Analysis Report",
            "=" * 70,
            f"  File: {results['metadata']['filepath']}",
            f"  MD5:  {results['metadata']['file_hashes'].get('md5', 'N/A')}",
            f"  Events Analyzed: {results['metadata']['total_events']:,}",
            f"  Time Range: {results['metadata']['time_range']['start']} → {results['metadata']['time_range']['end']}",
            "-" * 70,
            f"  THREAT SCORE: {score}% ({level})",
            f"  Findings: {results['summary']['total_findings']}",
            f"  Critical: {results['summary']['critical']} | High: {results['summary']['high']} | "
            f"Medium: {results['summary']['medium']} | Low: {results['summary']['low']}",
            f"  MITRE Techniques: {results['summary']['mitre_techniques']}",
            f"  IOCs Extracted: {results['summary']['total_iocs']}",
            f"  Correlations: {results['summary']['correlations']}",
            f"  Behavioral Chains: {results['summary']['behavioral_chains']}",
            "=" * 70,
        ]

        # Top findings
        if results["findings"]:
            lines.append("\n  TOP FINDINGS:")
            lines.append("-" * 70)
            for f in results["findings"][:20]:
                sev = f.get("severity", "").upper()
                lines.append(f"  [{sev}] {f.get('title', 'Unknown')} — {f.get('description', '')}")
                if f.get("mitre"):
                    lines.append(f"         MITRE: {f['mitre']}")
                lines.append(f"         Line: {f.get('line_number', 'N/A')}")

        # Correlations
        if results["correlations"]["correlations"]:
            lines.append(f"\n  ATTACK CORRELATIONS:")
            lines.append("-" * 70)
            for c in results["correlations"]["correlations"]:
                lines.append(f"  ⚡ [{c['severity'].upper()}] {c['name']}")
                lines.append(f"     {c['description']}")

        return "\n".join(lines)
