# 🛡️ ThreatScope — Advanced Log Intelligence & Threat Detection Engine

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/Version-2.0.0-brightgreen?style=for-the-badge)
![Rules](https://img.shields.io/badge/Detection%20Rules-116%2B-red?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-89%20Techniques-orange?style=for-the-badge)
![Categories](https://img.shields.io/badge/Attack%20Categories-19-purple?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)

**Built by [0xSABRY](https://github.com/0xsabry) — SOC Analyst & Threat Hunter**

</div>

---

## Overview

**ThreatScope** is a standalone, zero-dependency Windows log analysis and threat detection tool built in Python. It ingests `.log`, `.txt`, and `.evtx` (Windows Event Log) files and applies **116+ regex-powered detection rules** to surface threats, correlate multi-stage attack chains, extract IOCs, and map findings to MITRE ATT&CK techniques — all from a sleek dark-themed GUI.

> 🎯 Designed for SOC analysts, threat hunters, IR teams, and blue teamers who need rapid, offline log triage without spinning up a full SIEM.

---

## Features

| Feature                   | Details                                                           |
| ------------------------- | ----------------------------------------------------------------- |
| 🔍 **Detection Engine**   | 116+ rules, 256+ regex patterns, 19 attack categories             |
| 🎯 **MITRE ATT&CK**       | Full technique mapping (89 techniques tracked)                    |
| ⚡ **Correlation Engine** | 10 multi-signal attack chain rules                                |
| 🔎 **IOC Extraction**     | MD5/SHA1/SHA256, IPs, URLs, domains, emails, CVEs                 |
| 📄 **File Support**       | `.log`, `.txt`, `.evtx` (native + python-evtx)                    |
| 💾 **JSON Export**        | Full structured report with IOCs, MITRE, correlations             |
| 🖥️ **7-Tab GUI**          | Report, Findings, IP/Users, Timeline, MITRE ATT&CK, IOCs, Raw Log |
| 📊 **Threat Score**       | 0–100% weighted severity score with correlation bonuses           |
| ⚙️ **Zero Setup**         | Pure Python stdlib only (tkinter, re, json, struct)               |

---

## Attack Categories (19)

| #   | Category                | Rules | Key Threats                                                   |
| --- | ----------------------- | ----- | ------------------------------------------------------------- |
| 1   | Authentication          | 10    | Failed logins, brute-force, password spray, account creation  |
| 2   | Privilege Escalation    | 7     | UAC bypass, token theft, SeImpersonate, DLL hijacking         |
| 3   | Persistence             | 8     | Scheduled tasks, WMI subscriptions, COM hijack, BITS jobs     |
| 4   | Lateral Movement        | 8     | PsExec, Pass-the-Hash, SMB, WMI, DCOM, SSH                    |
| 5   | Command & Control       | 9     | Cobalt Strike, DNS tunneling, ICMP tunnel, domain fronting    |
| 6   | Exfiltration            | 6     | DNS exfil, cloud storage, steganography, clipboard            |
| 7   | Defense Evasion         | 10    | Log clearing, AMSI bypass, ETW bypass, ADS, obfuscation       |
| 8   | Discovery               | 7     | AD recon, network scan, BloodHound, security SW discovery     |
| 9   | Credential Access       | 5     | LSASS dump, DCSync, SAM dump, NTDS.dit, Mimikatz              |
| 10  | Web Attack              | 11    | SQLi, XSS, XXE, SSRF, RFI, deserialization, HTTP smuggling    |
| 11  | Malware                 | 8     | Ransomware, fileless malware, webshell, macros, droppers      |
| 12  | Auth Protocol Attack    | 3     | Kerberoasting, Golden/Silver Ticket, NTLM downgrade           |
| 13  | Cloud Attack            | 2     | Metadata service abuse, container escape                      |
| 14  | **Supply Chain** ⭐     | 3     | Dependency confusion, typosquatting, CI/CD compromise         |
| 15  | **IoT/OT Attack** ⭐    | 3     | SCADA/ICS, Modbus exploit, MQTT anomaly                       |
| 16  | **Insider Threat** ⭐   | 4     | Mass file access, off-hours, bulk download, USB exfil         |
| 17  | **Zero-Day/Exploit** ⭐ | 4     | Exploit kits, shellcode, heap spray, ROP chain                |
| 18  | **Email/Phishing** ⭐   | 4     | Phishing URLs, macro docs, spoofed sender, credential harvest |
| 19  | **Cryptomining** ⭐     | 3     | Mining pools, Stratum protocol, XMRig detection               |

> ⭐ New in v2.0.0

---

## Correlation Engine

ThreatScope automatically detects multi-stage attack chains by correlating signals across categories:

| Chain Name                    | Signals Required                                          | Boost |
| ----------------------------- | --------------------------------------------------------- | ----- |
| Credential Compromise Chain   | brute_force + privilege_escalation                        | +20   |
| Full Kill Chain Detected      | credential_dumping + lateral_movement + data_exfiltration | +30   |
| Ransomware Deployment Chain   | lateral_movement + av_tamper + ransomware                 | +25   |
| Active C2 with Exfiltration   | command_and_control + data_exfiltration                   | +20   |
| Persistence + Defense Evasion | persistence + log_tampering                               | +15   |
| AD Compromise Chain           | ad_recon + kerberoasting + golden_silver_ticket           | +30   |
| Phishing to Credential Dump   | phishing_url + credential_dumping                         | +20   |
| Web Attack to Shell           | sql_injection + reverse_shell                             | +20   |
| Supply Chain + Persistence    | dependency_confusion + persistence                        | +20   |
| Insider Threat Indicators     | off_hours_access + bulk_download                          | +15   |

---

## GUI Tabs

```
📋 Full Report     — Complete analysis report with all findings, IOCs, and recommendations
🚨 Findings        — Grouped by attack category with severity coloring
🌐 IP & Users      — Top IPs, usernames, and Event IDs
⏱  Timeline        — Chronological view of detected events + attack chains
🎯 MITRE ATT&CK    — Technique coverage table and category map
🔎 IOCs            — Extracted hashes, URLs, domains, emails, CVEs
📄 Raw Log         — First 2,000 lines of source log
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/0xsabry/ThreatScope.git
cd ThreatScope

# Run (Python 3.8+ required, no pip installs needed)
python 0xSABRY_ThreatScope.py

# Optional: install python-evtx for better EVTX parsing
pip install python-evtx
```

---

## Usage

1. **Launch** — `python 0xSABRY_ThreatScope.py`
2. **Load Log** — Click `📂 Load Log` and select a `.log`, `.txt`, or `.evtx` file
3. **Analyze** — Click `🔍 Analyze` — analysis runs in a background thread
4. **Review** — Navigate tabs to explore findings, timeline, MITRE coverage, and IOCs
5. **Export** — Click `💾 Export JSON` to save a structured machine-readable report

---

## JSON Export Schema (v2.0.0)

```json
{
  "tool": "0xSABRY ThreatScope",
  "version": "2.0.0",
  "threat_score": 85,
  "threat_level": "CRITICAL",
  "mitre_techniques_detected": [{"id": "T1003.001", "name": "LSASS Memory", "hits": 3}],
  "correlations": [{"name": "Full Kill Chain Detected", "severity": "CRITICAL"}],
  "iocs": {"sha256": [...], "url": [...], "cve": [...]},
  "findings_summary": {"credential_dumping": {"count": 3, "mitre": "T1003.001"}},
  "findings_detail": {"credential_dumping": [{"line": 42, "content": "..."}]}
}
```

---

## Threat Scoring

| Score  | Level       | Color                                |
| ------ | ----------- | ------------------------------------ |
| 80–100 | CRITICAL 🔴 | Immediate incident response required |
| 60–79  | HIGH 🟠     | Urgent investigation needed          |
| 40–59  | MEDIUM 🟡   | Active monitoring and review         |
| 20–39  | LOW 🟢      | Document and track                   |
| 0–19   | MINIMAL ⚪  | Continue routine monitoring          |

Scores use diminishing returns for repeated same-rule hits, with flat bonuses applied when correlation chains are triggered.

---

## Supported Event IDs

| Event ID  | Description                          |
| --------- | ------------------------------------ |
| 4624      | Successful Logon                     |
| 4625      | Failed Logon                         |
| 4648      | Explicit Credential Logon            |
| 4672      | Special Privileges Assigned          |
| 4698/4702 | Scheduled Task Created/Modified      |
| 4720      | User Account Created                 |
| 4740      | Account Locked Out                   |
| 4769      | Kerberos TGS Requested               |
| 4778/4779 | RDP Session Reconnected/Disconnected |
| 5140/5145 | Network Share Accessed               |
| 7045      | New Service Installed                |
| 1102/104  | Audit Log Cleared                    |
| 5861      | WMI Event Subscription               |

---

## License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
Made with ❤️ by <a href="https://github.com/0xsabry">0xSABRY</a> — SOC Analyst & Security Researcher
</div>
