# 🛡️ ThreatScope — Advanced Log Intelligence & Threat Detection Engine

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/Version-3.0.0-brightgreen?style=for-the-badge)
![Rules](https://img.shields.io/badge/Detection%20Rules-115%2B-red?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-97%20Techniques-orange?style=for-the-badge)
![Categories](https://img.shields.io/badge/Attack%20Categories-25-purple?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)
![STIX](https://img.shields.io/badge/STIX%202.1-IOC%20Export-cyan?style=for-the-badge)
![Sigma](https://img.shields.io/badge/Sigma-Rule%20Support-yellow?style=for-the-badge)

**Built by [0xSABRY](https://github.com/0xsabry) — SOC Analyst & Threat Hunter**

</div>

---

## Overview

**ThreatScope** is a standalone, zero-dependency Windows log analysis and threat detection tool built in Python. It ingests `.log`, `.txt`, and `.evtx` (Windows Event Log) files and applies **115+ regex-powered detection rules** to surface threats, correlate multi-stage attack chains, extract IOCs, and map findings to MITRE ATT&CK techniques — all from a sleek dark-themed GUI or the command line.

> 🎯 Designed for SOC analysts, threat hunters, IR teams, and blue teamers who need rapid, offline log triage without spinning up a full SIEM.

---

## ⭐ What's New in v3.0.0

| Feature                     | Description                                                                    |
| --------------------------- | ------------------------------------------------------------------------------ |
| 🖥️ **CLI Mode**             | Full command-line analysis with `--file`, `--json`, `--report`, `--stix` flags |
| 🔐 **30+ New Rules**        | API Security, AI/ML Attacks, Blockchain, Network, Zero Trust categories        |
| 🔗 **STIX 2.1 Export**      | Export IOCs as STIX bundles for threat intel platform sharing                  |
| 📐 **Sigma Rule Support**   | Load custom YAML detection rules from `sigma_rules/` directory                 |
| 🔒 **File Integrity**       | Auto MD5/SHA256 hash of analyzed log files in reports                          |
| ⚡ **15 Correlation Rules** | 5 new attack chain detections (API, AI, MFA, Crypto, MitM)                     |
| 📊 **97 MITRE Techniques**  | Expanded technique mapping with new tactic coverage                            |

---

## Features

| Feature                   | Details                                                           |
| ------------------------- | ----------------------------------------------------------------- |
| 🔍 **Detection Engine**   | 115+ rules, 300+ regex patterns, 25 attack categories             |
| 🎯 **MITRE ATT&CK**       | Full technique mapping (97 techniques tracked)                    |
| ⚡ **Correlation Engine** | 15 multi-signal attack chain rules                                |
| 🔎 **IOC Extraction**     | MD5/SHA1/SHA256, IPs, URLs, domains, emails, CVEs                 |
| 📄 **File Support**       | `.log`, `.txt`, `.evtx` (native + python-evtx)                    |
| 💾 **JSON Export**        | Full structured report with IOCs, MITRE, correlations             |
| 🔗 **STIX 2.1 Export**    | Standard IOC bundle for threat intel platforms                    |
| 📐 **Sigma Rules**        | Import YAML-based detection rules                                 |
| 🖥️ **7-Tab GUI**          | Report, Findings, IP/Users, Timeline, MITRE ATT&CK, IOCs, Raw Log |
| ⌨️ **CLI Mode**           | Headless analysis for automation and scripting                    |
| 📊 **Threat Score**       | 0–100% weighted severity score with correlation bonuses           |
| 🔒 **File Integrity**     | MD5/SHA256 hash verification for analyzed files                   |
| ⚙️ **Zero Setup**         | Pure Python stdlib only (tkinter, re, json, struct)               |

---

## Attack Categories (25)

| #   | Category                 | Rules | Key Threats                                                    |
| --- | ------------------------ | ----- | -------------------------------------------------------------- |
| 1   | Authentication           | 10    | Failed logins, brute-force, password spray, account creation   |
| 2   | Privilege Escalation     | 7     | UAC bypass, token theft, SeImpersonate, DLL hijacking          |
| 3   | Persistence              | 8     | Scheduled tasks, WMI subscriptions, COM hijack, BITS jobs      |
| 4   | Lateral Movement         | 8     | PsExec, Pass-the-Hash, SMB, WMI, DCOM, SSH                     |
| 5   | Command & Control        | 9     | Cobalt Strike, DNS tunneling, ICMP tunnel, domain fronting     |
| 6   | Exfiltration             | 6     | DNS exfil, cloud storage, steganography, clipboard             |
| 7   | Defense Evasion          | 10    | Log clearing, AMSI bypass, ETW bypass, ADS, obfuscation        |
| 8   | Discovery                | 7     | AD recon, network scan, BloodHound, security SW discovery      |
| 9   | Credential Access        | 5     | LSASS dump, DCSync, SAM dump, NTDS.dit, Mimikatz               |
| 10  | Web Attack               | 11    | SQLi, XSS, XXE, SSRF, RFI, deserialization, HTTP smuggling     |
| 11  | Malware                  | 8     | Ransomware, fileless malware, webshell, macros, droppers       |
| 12  | Auth Protocol Attack     | 3     | Kerberoasting, Golden/Silver Ticket, NTLM downgrade            |
| 13  | Cloud Attack             | 2     | Metadata service abuse, container escape                       |
| 14  | Supply Chain             | 3     | Dependency confusion, typosquatting, CI/CD compromise          |
| 15  | IoT/OT Attack            | 3     | SCADA/ICS, Modbus exploit, MQTT anomaly                        |
| 16  | Insider Threat           | 4     | Mass file access, off-hours, bulk download, USB exfil          |
| 17  | Zero-Day/Exploit         | 4     | Exploit kits, shellcode, heap spray, ROP chain                 |
| 18  | Email/Phishing           | 4     | Phishing URLs, macro docs, spoofed sender, credential harvest  |
| 19  | Cryptomining             | 3     | Mining pools, Stratum protocol, XMRig detection                |
| 20  | **API Security** ⭐      | 7     | JWT abuse, GraphQL injection, BOLA/IDOR, OAuth theft           |
| 21  | **AI/ML Attack** ⭐      | 4     | Prompt injection, model poisoning, adversarial input           |
| 22  | **Blockchain Attack** ⭐ | 4     | Smart contract exploit, wallet theft, rug pull, crypto clipper |
| 23  | **Network Attack** ⭐    | 6     | ARP poisoning, DNS rebinding, BGP hijack, SSL stripping        |
| 24  | **Zero Trust Bypass** ⭐ | 6     | MFA fatigue, SAML forgery, Kerberos delegation abuse           |
| 25  | **Sigma Rule** ⭐        | ∞     | Custom YAML-based detection rules                              |

> ⭐ New in v3.0.0

---

## Installation

```bash
# Clone the repository
git clone https://github.com/0xsabry/ThreatScope.git
cd ThreatScope

# Run (Python 3.8+ required, no pip installs needed)
python 0xSABRY_ThreatScope.py

# Optional: install enhanced dependencies
pip install -r requirements.txt
```

---

## Usage

### GUI Mode (Default)

```bash
python 0xSABRY_ThreatScope.py
```

1. **Load Log** — Click `📂 Load Log` and select a `.log`, `.txt`, or `.evtx` file
2. **Analyze** — Click `🔍 Analyze` — analysis runs in a background thread
3. **Review** — Navigate tabs to explore findings, timeline, MITRE coverage, and IOCs
4. **Export** — Click `💾 Export JSON` or `🔗 Export STIX` for machine-readable reports

### CLI Mode (Headless)

```bash
# Analyze and print text report
python 0xSABRY_ThreatScope.py -f server.log --report

# Analyze and export JSON report
python 0xSABRY_ThreatScope.py -f data.evtx -j report.json

# Export IOCs as STIX 2.1 bundle
python 0xSABRY_ThreatScope.py -f log.txt --stix iocs.json

# Full analysis with all exports
python 0xSABRY_ThreatScope.py -f access.log -r -j report.json --stix iocs.json
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
ThreatScope/
├── 0xSABRY_ThreatScope.py      # Main application (GUI + CLI + Engine)
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

## Correlation Engine (15 Rules)

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
| **API Attack Chain** ⭐       | jwt_abuse + broken_auth_api                               | +20   |
| **AI System Compromise** ⭐   | prompt_injection + data_extraction_llm                    | +25   |
| **MFA Bypass + Lateral** ⭐   | mfa_fatigue + lateral_movement                            | +25   |
| **Crypto Theft Chain** ⭐     | wallet_theft + crypto_clipper                             | +25   |
| **Network MitM + Creds** ⭐   | arp_poisoning + credential_dumping                        | +20   |

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
Made with ❤️ by <a href="https://github.com/0xsabry">0xSABRY</a> — SOC Analyst & Security Researcher
</div>
