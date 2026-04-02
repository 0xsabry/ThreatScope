# ⚡ ThreatscopeX — Advanced Log Intelligence & Threat Detection Engine

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Rules](https://img.shields.io/badge/Detection%20Rules-308-red?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-274%20Techniques-orange?style=for-the-badge)
![Correlations](https://img.shields.io/badge/Correlation%20Rules-35-purple?style=for-the-badge)
![Categories](https://img.shields.io/badge/Attack%20Categories-24-darkblue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)
![STIX](https://img.shields.io/badge/STIX%202.1-IOC%20Export-cyan?style=for-the-badge)
![Sigma](https://img.shields.io/badge/Sigma-Rule%20Support-yellow?style=for-the-badge)

**Built by [0xSABRY](https://github.com/0xsabry) — SOC Analyst & Threat Hunter**

</div>

---

## Overview

**ThreatscopeX** is a high-performance, enterprise-grade log analysis and threat detection engine built in Python. It ingests `.log`, `.txt`, `.evtx`, `.csv`, and `.json` files and applies **308 regex-powered detection rules** across **24 attack categories** to detect threats, correlate multi-stage attack chains, extract IOCs, and map findings to **274 MITRE ATT&CK techniques** — all from a premium dark-themed GUI or the command line.

> 🎯 Designed for SOC analysts, threat hunters, IR teams, and blue teamers who need rapid, offline log triage without spinning up a full SIEM.

---

## Features

| Feature                    | Details                                                              |
| -------------------------- | -------------------------------------------------------------------- |
| 🔍 **Detection Engine**    | 308 rules, 900+ regex patterns, 24 attack categories                |
| 🎯 **MITRE ATT&CK**       | Full technique mapping (274 techniques across all 14 tactics)        |
| ⚡ **Correlation Engine**  | 35 multi-signal attack chain detection rules                        |
| 🔎 **IOC Extraction**      | MD5/SHA1/SHA256, IPv4/IPv6, URLs, domains, emails, CVEs, Bitcoin, MAC, registry keys, file paths, user-agents |
| 📄 **File Support**        | `.log`, `.txt`, `.evtx` (native + python-evtx), `.csv`, `.json`     |
| 💾 **JSON Export**          | Full structured report with IOCs, MITRE, correlations                |
| 🔗 **STIX 2.1 Export**     | Standard IOC bundle for threat intel platforms                       |
| 📐 **Sigma Rules**         | Import YAML-based detection rules                                    |
| 🖥️ **8-Tab Premium GUI**   | Report, Findings, IP/Users, Timeline, MITRE ATT&CK, IOCs, Rule Browser, Raw Log |
| 📚 **Rule Browser**        | Search, filter, and browse all 308 rules by category/severity        |
| ⌨️ **CLI Mode**            | Headless analysis for automation and scripting                       |
| 📊 **Threat Score**        | 0–100% weighted severity score with correlation bonuses              |
| 🔒 **File Integrity**      | MD5/SHA256 hash verification for analyzed files                      |
| ⚙️ **Zero Setup**          | Pure Python stdlib only (tkinter, re, json, struct)                  |

---

## Attack Categories (24)

| #   | Category              | Rules | Key Threats                                                    |
| --- | --------------------- | ----- | -------------------------------------------------------------- |
| 1   | Authentication        | 30    | Failed logins, brute-force, password spray, SID history, SPN   |
| 2   | Privilege Escalation  | 21    | UAC bypass, token theft, Potato exploits, Zerologon, PwnKit    |
| 3   | Persistence           | 31    | Registry run keys, WMI, COM hijack, BITS, kernel modules       |
| 4   | Lateral Movement      | 20    | PsExec, Pass-the-Hash/Ticket, RDP hijack, CrackMapExec        |
| 5   | C2                    | 24    | Cobalt Strike, DNS tunneling, domain fronting, Mythic, Sliver  |
| 6   | Exfiltration          | 15    | DNS exfil, cloud storage, USB, steganography, keylogger        |
| 7   | Defense Evasion       | 30    | AMSI/ETW bypass, process injection, rootkit, NTDLL unhooking   |
| 8   | Discovery             | 20    | AD recon, BloodHound, cloud enum, SNMP/LDAP enum               |
| 9   | Credential Access     | 20    | LSASS dump, DCSync, Kerberoasting, AS-REP roast, DPAPI         |
| 10  | Web Attack            | 20    | SQLi, XSS, SSRF, Log4Shell, Spring4Shell, deserialization      |
| 11  | Malware               | 21    | Ransomware (LockBit/BlackCat), RATs, APT tools, Mimikatz       |
| 12  | Cloud Attack          | 2     | Metadata service abuse, container escape                       |
| 13  | Supply Chain          | 3     | Dependency confusion, typosquatting, CI/CD compromise          |
| 14  | IoT/OT Attack         | 3     | SCADA/ICS, Modbus exploit, MQTT anomaly                        |
| 15  | Insider Threat        | 3     | Mass file access, off-hours, bulk download                     |
| 16  | Zero-Day/Exploit      | 4     | Exploit kits, shellcode, heap spray, ROP chain                 |
| 17  | Email/Phishing        | 4     | Phishing URLs, macro docs, spoofed sender, credential harvest  |
| 18  | Cryptomining          | 3     | Mining pools, Stratum protocol, XMRig detection                |
| 19  | API Security          | 7     | JWT abuse, GraphQL injection, BOLA/IDOR, OAuth theft           |
| 20  | AI/ML Attack          | 4     | Prompt injection, model poisoning, adversarial input           |
| 21  | Blockchain Attack     | 4     | Smart contract exploit, wallet theft, rug pull, crypto clipper |
| 22  | Network Attack        | 6     | ARP poisoning, DNS rebinding, BGP hijack, SSL stripping        |
| 23  | Zero Trust Bypass     | 6     | MFA fatigue, SAML forgery, Kerberos delegation abuse           |
| 24  | Execution             | 10    | PowerShell, WMI, certutil, BITSAdmin, Office child process     |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/0xsabry/ThreatScope.git
cd ThreatScope

# Run (Python 3.8+ required, no pip installs needed)
python ThreatscopeX.py

# Optional: install enhanced dependencies
pip install -r requirements.txt
```

---

## Usage

### GUI Mode (Default)

```bash
python ThreatscopeX.py
```

1. **Load Log** — Click `📂 Load Log File` and select a `.log`, `.txt`, `.evtx`, `.csv`, or `.json` file
2. **Analyze** — Click `⚡ Analyze` — analysis runs in a background thread
3. **Review** — Navigate 8 tabs: Report, Findings, IP/Users, Timeline, MITRE ATT&CK, IOCs, Rule Browser, Raw Log
4. **Export** — Click `💾 Export JSON` or `🔗 Export STIX` for machine-readable reports

### CLI Mode (Headless)

```bash
# Analyze and print text report
python ThreatscopeX.py -f server.log --report

# Analyze and export JSON report
python ThreatscopeX.py -f data.evtx -j report.json

# Export IOCs as STIX 2.1 bundle
python ThreatscopeX.py -f log.txt --stix iocs.json

# Full analysis with all exports
python ThreatscopeX.py -f access.log -r -j report.json --stix iocs.json
```

| Flag             | Description                         |
| ---------------- | ----------------------------------- |
| `-f`, `--file`   | Path to log file (required for CLI) |
| `-r`, `--report` | Print text report to stdout         |
| `-j`, `--json`   | Export JSON report to path          |
| `--stix`         | Export STIX 2.1 IOC bundle          |

---

## Sigma Rule Support

Place Sigma-format YAML files in `sigma_rules/` to extend detection:

```yaml
title: Suspicious PowerShell Encoded Command
level: high
tags:
  - attack.t1059.001
detection:
  keywords:
    - "powershell -encodedcommand"
    - "powershell -w hidden"
  condition: keywords
```

Rules are automatically loaded during analysis. Install `pyyaml` for Sigma support:

```bash
pip install pyyaml
```

---

## Project Structure

```
ThreatScopeX/
├── ThreatscopeX.py              # Main application (GUI + CLI + Engine)
├── requirements.txt             # Optional dependencies
├── sigma_rules/                 # Custom Sigma detection rules (YAML)
│   └── example_powershell.yml   # Example Sigma rule
├── sample_anonymous_report.json # Sample analysis output
├── sample_anyonomus login.evtx  # Sample EVTX log for testing
├── CONTRIBUTING.md              # Contribution guidelines
├── SECURITY.md                  # Vulnerability reporting policy
├── LICENSE                      # MIT License
└── README.md                    # This file
```

---

## Correlation Engine (35 Rules)

| Chain Name                    | Signals Required                                          | Boost |
| ----------------------------- | --------------------------------------------------------- | ----- |
| Credential Compromise Chain   | brute_force + privilege_escalation                        | +20   |
| Full Kill Chain Detected      | credential_dumping + lateral_movement + data_exfiltration | +30   |
| Ransomware Deployment Chain   | lateral_movement + av_tamper + ransomware                 | +25   |
| Active C2 with Exfiltration   | command_and_control + data_exfiltration                   | +20   |
| AD Compromise Chain           | ad_recon + kerberoasting + golden_silver_ticket           | +30   |
| DCSync + Golden Ticket        | dcsync_attack + golden_silver_ticket                      | +30   |
| Ransomware Kill Chain         | credential_dumping + lateral_movement + ransomware        | +30   |
| ICS Attack Chain              | scada_ics_abuse + modbus_exploit                          | +30   |
| Zero-Day Exploitation         | shellcode_detect + process_injection                      | +28   |
| SAML Forgery + Cloud Access   | saml_attack + cloud_metadata_abuse                        | +28   |
| Rootkit + Timestomping        | rootkit_detect + timestomp                                | +28   |
| AI System Compromise          | prompt_injection + data_extraction_llm                    | +25   |
| MFA Bypass + Lateral          | mfa_fatigue + lateral_movement                            | +25   |
| Crypto Theft Chain            | wallet_theft + crypto_clipper                             | +25   |
| Container Escape + Persistence| container_escape + persistence                            | +25   |
| Log4Shell Exploitation        | log4j_exploit + reverse_shell                             | +25   |
| PrintNightmare Chain          | lpe_printspooler + lateral_movement                       | +25   |
| Trojan + C2 Beacon            | trojan_rat + beacon_pattern                               | +25   |
| AS-REP + Pass-the-Ticket      | as_rep_roasting + pass_the_ticket                         | +25   |
| LOLBins Attack Chain          | fileless_malware + amsi_bypass                            | +20   |
| ... and 15 more               |                                                           |       |

---

## Threat Scoring

| Score  | Level       | Action                               |
| ------ | ----------- | ------------------------------------ |
| 80–100 | CRITICAL 🔴 | Immediate incident response required |
| 60–79  | HIGH 🟠     | Urgent investigation needed          |
| 40–59  | MEDIUM 🟡   | Active monitoring and review         |
| 20–39  | LOW 🟢      | Document and track                   |
| 0–19   | MINIMAL ⚪  | Continue routine monitoring          |

---

## License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">

Built with ❤️ by <a href="https://github.com/0xsabry">0xSABRY</a> — SOC Analyst & Security Researcher

[![LinkedIn](https://img.shields.io/badge/Connect_on_LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/mohamed-sabry-hamdan/)
[![GitHub](https://img.shields.io/badge/Follow_on_GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/0xsabry)

</div>
