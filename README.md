<p align="center">
  <img src="https://img.shields.io/badge/ThreatScope-V3-00d4ff?style=for-the-badge&logo=shield&logoColor=white" alt="ThreatScope V3"/>
</p>

<h1 align="center">🛡️ ThreatScope V3</h1>

<p align="center">
  <strong>Advanced DFIR & Threat Detection Platform</strong><br>
  <em>Open-source forensic analysis tool that eats Chainsaw for breakfast.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/SigmaHQ-3000%2B%20Rules-blue?style=flat-square" alt="Sigma Rules"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-100%2B%20Techniques-red?style=flat-square" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/Detection%20Rules-55%2B%20Categories-purple?style=flat-square" alt="Detection Rules"/>
  <img src="https://img.shields.io/badge/Author-0xSABRY-ff1744?style=flat-square" alt="Author"/>
</p>

---

## 🚀 What is ThreatScope V3?

ThreatScope V3 is a **world-class DFIR and threat detection platform** designed for SOC analysts, incident responders, and threat hunters. It combines the power of Sigma rules, behavioral chain detection, AI-powered analysis, and multi-platform log parsing into one unified tool — now with **live monitoring**, **extended Linux support**, **20+ YARA rules**, and **security-hardened architecture**.

### What's New in V3

- 🐧 **Full Linux Log Support** — Dedicated parsers for syslog, auth.log, journald, Apache/Nginx, and firewall logs
- 📡 **Live Log Monitoring** — Real-time WebSocket-based streaming with instant detection
- 🛡️ **20+ Built-in YARA Rules** — Malware signatures, webshells, exploit tools, suspicious documents, Linux threats
- 🎯 **100+ MITRE ATT&CK Techniques** — Full coverage across all 14 tactics with sub-technique resolution
- ⚔️ **55+ Detection Categories** — 30 new patterns including cloud attacks, cryptojacking, fileless malware, and more
- 🔐 **Security Hardened** — CSP headers, rate limiting, CSRF protection, input validation, audit logging
- 🕵️ **20 APT Groups** — 10 new groups including Volt Typhoon, Scattered Spider, LockBit, ALPHV/BlackCat
- 🔗 **30 Correlation Rules** — 10 new rules for Linux, cloud, and advanced attack chains
- ⛓️ **15 Behavioral Chains** — 5 new multi-stage patterns for Linux and cloud attack sequences

### Why ThreatScope?

| Feature | ThreatScope V3 | Chainsaw | Others |
|---------|:-:|:-:|:-:|
| SigmaHQ Full Integration (3000+ Rules) | ✅ | ✅ | ❌ |
| YARA Rules Engine (20+ Built-in) | ✅ | ✅ | ❌ |
| Behavioral Chain Detection (15 Chains) | ✅ | ❌ | ❌ |
| Multi-Platform (Win/Linux/Mac/Cloud) | ✅ | ❌ | ❌ |
| Full Linux Log Parsing (5 Parsers) | ✅ | ❌ | ❌ |
| Live Log Monitoring (WebSocket) | ✅ | ❌ | ❌ |
| AI Copilot & Narrative Engine | ✅ | ❌ | ❌ |
| APT Group Attribution (20 Groups) | ✅ | ❌ | ❌ |
| Threat Intel Enrichment (VT/AbuseIPDB/OTX) | ✅ | ❌ | ❌ |
| Modern Web Dashboard | ✅ | ❌ | ❌ |
| 100+ MITRE ATT&CK Techniques | ✅ | ❌ | ❌ |
| Security Hardened (CSP/Rate Limiting/Audit) | ✅ | ❌ | ❌ |
| False Positive Suppression | ✅ | ❌ | ❌ |
| Training Mode for Analysts | ✅ | ❌ | ❌ |
| Multi-Format Export (JSON/CSV/STIX/PDF/DOCX) | ✅ | ❌ | ❌ |

---

## ✨ Key Features

### 🔍 Detection Power
- **55+ Built-in Detection Categories** — Advanced regex patterns covering cloud, Linux, network, and application attacks
- **SigmaHQ Integration** — Auto-sync and parse 3000+ Sigma rules with full condition support
- **YARA Scanning** — 20+ built-in rules for malware, webshells, exploit tools, and suspicious documents
- **Behavioral Chain Detection** — 15 multi-stage attack patterns with time-window correlation
- **30 Correlation Rules** — Kill chain analysis and score boosting

### 🐧 Linux Log Support (V3 NEW)
- **Syslog Parser** — RFC 3164/5424 with facility/severity extraction
- **Auth Log Parser** — SSH login, sudo, PAM, account management events
- **Journald Parser** — systemd journal JSON exports with full metadata
- **Apache/Nginx Parser** — Access and error logs with suspicious request flagging
- **Firewall Parser** — iptables/nftables/ufw with action and protocol extraction

### 📡 Live Monitoring (V3 NEW)
- **Real-time Log Tailing** — Tail live log files with instant detection
- **Multi-file Monitoring** — Monitor multiple files simultaneously
- **Live Alert Stream** — Real-time alert cards with severity color-coding
- **Statistics Dashboard** — Events/sec, alerts, critical findings counters

### 🌐 Multi-Platform Parsers
- Windows EVTX & Sysmon
- Linux syslog, auth.log, journald, firewall
- Apache/Nginx access & error logs
- macOS Unified Logs
- AWS CloudTrail
- Azure Activity Logs
- GCP Cloud Audit Logs
- Generic text/syslog

### 🧠 AI Analysis Core
- **Attack Narrative Engine** — Generates professional incident reports from findings
- **Analyst Copilot** — Chat interface for Q&A grounded in session data
- **Training Mode** — Socratic educational approach for junior analysts

### 📡 Threat Intelligence
- VirusTotal, AbuseIPDB, AlienVault OTX API integration
- APT Group Attribution (20 groups: APT28, APT29, Lazarus, Volt Typhoon, Scattered Spider, etc.)
- CVE/NVD Feed with exploit checks
- Cached lookups with rate limiting

### 🎨 Modern Web UI
- Premium dark-themed cybersecurity aesthetic
- Interactive dashboards with severity charts
- Attack timeline visualization
- MITRE ATT&CK heatmap
- AI Copilot chat interface
- Live monitoring dashboard

### 🔐 Security Hardening (V3 NEW)
- Content Security Policy (CSP) headers
- X-Frame-Options, X-Content-Type-Options, HSTS
- In-memory rate limiting per IP with auto-blocking
- Input validation and path traversal prevention
- File upload magic byte validation
- Audit logging with IP anonymization

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/0xsabry/ThreatscopeX.git
cd ThreatscopeX

# Install dependencies
pip install -r requirements.txt

# Optional: Install AI and reporting features
pip install reportlab python-docx yara-python
```

### Launch Web Dashboard

```bash
# Start the web interface
python app.py

# Or via CLI
python cli.py web --host 127.0.0.1 --port 5000
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

### CLI Analysis

```bash
# Analyze a Windows event log
python cli.py analyze path/to/Security.evtx -r

# Analyze a Linux auth.log
python cli.py analyze /var/log/auth.log -r

# Analyze with JSON export
python cli.py analyze path/to/access.log -o report.json -f json

# Analyze with STIX 2.1 export
python cli.py analyze path/to/events.json -o stix_bundle.json -f stix

# Sync Sigma rules from SigmaHQ
python cli.py sync
```

### Live Monitoring

```bash
# Start web UI then navigate to /live-monitor
python app.py
# Open http://127.0.0.1:5000/live-monitor

# Or use the API:
curl -X POST http://127.0.0.1:5000/api/live/start \
  -H "Content-Type: application/json" \
  -d '{"path": "/var/log/auth.log"}'
```

### API Configuration

Set these environment variables for full functionality:

```bash
# AI Features
export OPENAI_API_KEY="your_key"

# Threat Intelligence
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"

# Security (optional)
export FLASK_SECRET_KEY="your_secret_key"
```

---

## 📁 Project Structure

```
ThreatscopeX/
├── app.py                      # Flask web application (security-hardened)
├── cli.py                      # Enhanced CLI interface
├── config.py                   # Global configuration (V3 hardened)
├── requirements.txt            # Dependencies
├── core/
│   ├── analyzer.py             # Main analysis orchestrator (55+ patterns)
│   ├── sigma_engine.py         # Full Sigma rule parser
│   ├── sigma_sync.py           # SigmaHQ auto-sync
│   ├── behavioral_chain.py     # 15 multi-stage attack chains
│   ├── yara_engine.py          # YARA scanning engine
│   ├── ioc_extractor.py        # IOC extraction engine
│   ├── correlation.py          # 30 correlation rules
│   ├── false_positive.py       # FP suppression engine
│   ├── realtime_monitor.py     # File change monitoring
│   ├── live_monitor.py         # V3: Live log tailing & detection
│   └── security.py             # V3: Security hardening module
├── parsers/
│   ├── log_parsers.py          # Multi-platform log parsers + auto-detection
│   └── linux_parsers.py        # V3: Dedicated Linux log parsers
├── intel/
│   ├── enrichment.py           # VT/AbuseIPDB/OTX enrichment
│   └── apt_mapper.py           # 20 APT groups + 100+ MITRE techniques
├── ai/
│   └── ai_core.py              # Narrative, Copilot, Training
├── export/
│   └── exporters.py            # JSON/CSV/STIX/PDF/DOCX
├── yara_rules/
│   ├── malware_signatures.yar  # V3: Cobalt Strike, Mimikatz, ransomware, RATs
│   ├── webshells.yar           # V3: PHP/ASP/JSP webshells
│   ├── exploit_tools.yar       # V3: Privesc, credential dump, lateral movement tools
│   ├── suspicious_documents.yar# V3: Malicious macros, PE in docs, PDF exploits
│   └── linux_threats.yar       # V3: Rootkits, crypto miners, Linux backdoors
├── templates/                  # Jinja2 HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── analysis.html
│   ├── timeline.html
│   ├── mitre.html
│   ├── intel.html
│   ├── copilot.html
│   ├── rules.html
│   ├── settings.html
│   └── live_monitor.html       # V3: Real-time monitoring UI
└── static/
    ├── css/style.css           # Premium dark theme
    └── js/app.js               # Frontend logic
```

---

## 🎯 MITRE ATT&CK Coverage

ThreatScope V3 maps findings to **100+ MITRE ATT&CK techniques** across all **14 tactics** and provides:
- Interactive heatmap visualization
- APT group attribution (20 groups)
- Kill chain coverage analysis
- Technique-to-tactic mapping
- Sub-technique resolution

---

## 🛡️ Built-in Detection Categories (55+)

### Original Categories (25)
1. Brute Force & Authentication Attacks
2. Credential Dumping (Mimikatz, LSASS)
3. Privilege Escalation (UAC Bypass, Token Manipulation)
4. Lateral Movement (PsExec, WMI, SMB)
5. Data Exfiltration
6. Persistence Mechanisms
7. Command & Control (Cobalt Strike, Empire)
8. Ransomware Indicators
9. Log Tampering & Anti-Forensics
10. Reverse Shells
11. SQL Injection
12. PowerShell Abuse
13. AV/Security Tool Tampering
14. Kerberoasting & Golden/Silver Ticket
15. Active Directory Reconnaissance
16. Phishing & Social Engineering
17. Container Escape
18. ARP Poisoning
19. MFA Fatigue Attacks
20. JWT Token Abuse
21. AI Prompt Injection
22. Network Discovery
23. WMI Abuse
24. Scheduled Task Persistence
25. Off-Hours Access

### V3 Extended Categories (30+)
26. Linux SSH Brute Force
27. Linux Rootkit Indicators
28. Linux Cron Persistence
29. Linux Privilege Escalation
30. Cryptojacking
31. Supply Chain Attack
32. Cloud IAM Abuse
33. Cloud Storage Exfiltration
34. API BOLA/IDOR
35. DNS Tunneling
36. DGA Detection
37. WAF Bypass
38. SSRF Attacks
39. XXE Injection
40. Deserialization Attacks
41. Memory Injection
42. Boot Persistence
43. Firmware Attacks
44. Keylogger Activity
45. Clipboard Hijacking
46. Screen Capture
47. Crypto Wallet Theft
48. WiFi Attacks
49. USB Device Abuse
50. Email Compromise
51. Zero-Day Indicators
52. Fileless Malware
53. Active Directory DCSync
54. Cloud Logging Tampering
55. Linux Shell Escape

---

## 📊 Export Formats

| Format | Description |
|--------|-------------|
| JSON | Full analysis results with all findings and metadata |
| CSV | Flat findings table for spreadsheet analysis |
| STIX 2.1 | Standard threat intelligence sharing format |
| PDF | Professional executive report with charts |
| DOCX | Editable Word document for incident reports |

---

## 🕵️ APT Group Database (20 Groups)

| Group | Country | Aliases |
|-------|---------|---------|
| APT28 | Russia | Fancy Bear, Sofacy, STRONTIUM |
| APT29 | Russia | Cozy Bear, NOBELIUM |
| APT41 | China | Winnti, BARIUM, Double Dragon |
| Lazarus | North Korea | HIDDEN COBRA, Zinc |
| APT1 | China | Comment Crew, PLA Unit 61398 |
| FIN7 | Russia | Carbanak, Carbon Spider |
| Sandworm | Russia | Voodoo Bear, IRIDIUM |
| Turla | Russia | Snake, Venomous Bear |
| APT32 | Vietnam | OceanLotus, Canvas Cyclone |
| MuddyWater | Iran | MERCURY, Static Kitten |
| **Kimsuky** | North Korea | Velvet Chollima, Thallium |
| **Gamaredon** | Russia | Primitive Bear, Shuckworm |
| **Charming Kitten** | Iran | APT35, Mint Sandstorm |
| **Hafnium** | China | Silk Typhoon |
| **Darkside** | Russia | BlackMatter |
| **REvil** | Russia | Sodinokibi, GoldSouthfield |
| **Volt Typhoon** | China | Bronze Silhouette |
| **Scattered Spider** | International | UNC3944, Roasted 0ktapus |
| **LockBit** | Russia | LockBit 3.0, LockBitSupp |
| **ALPHV/BlackCat** | Russia | BlackCat, Noberus |

*Bold = V3 additions*

---

## 📝 License

MIT License — see [LICENSE](LICENSE)

---

## 👨‍💻 Author

**Mohamed Sabry (0xSABRY)**
- SOC Analyst & Threat Hunter
- Founder of Zero2Aura
- [GitHub](https://github.com/0xsabry)

---

<p align="center">
  <strong>⭐ Star this repo if ThreatScope helps your investigations! ⭐</strong>
</p>
