<p align="center">
  <img src="https://img.shields.io/badge/ThreatScope-V2-00d4ff?style=for-the-badge&logo=shield&logoColor=white" alt="ThreatScope V2"/>
</p>

<h1 align="center">🛡️ ThreatScope V2</h1>

<p align="center">
  <strong>Advanced DFIR & Threat Detection Platform</strong><br>
  <em>Open-source forensic analysis tool that eats Chainsaw for breakfast.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/SigmaHQ-3000%2B%20Rules-blue?style=flat-square" alt="Sigma Rules"/>
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=flat-square" alt="MITRE ATT&CK"/>
  <img src="https://img.shields.io/badge/Author-0xSABRY-ff1744?style=flat-square" alt="Author"/>
</p>

---

## 🚀 What is ThreatScope V2?

ThreatScope V2 is a **world-class DFIR and threat detection platform** designed for SOC analysts, incident responders, and threat hunters. It combines the power of Sigma rules, behavioral chain detection, AI-powered analysis, and multi-platform log parsing into one unified tool.

### Why ThreatScope?

| Feature | ThreatScope V2 | Chainsaw | Others |
|---------|:-:|:-:|:-:|
| SigmaHQ Full Integration (3000+ Rules) | ✅ | ✅ | ❌ |
| YARA Rules Engine | ✅ | ✅ | ❌ |
| Behavioral Chain Detection | ✅ | ❌ | ❌ |
| Multi-Platform (Win/Linux/Mac/Cloud) | ✅ | ❌ | ❌ |
| AI Copilot & Narrative Engine | ✅ | ❌ | ❌ |
| APT Group Attribution | ✅ | ❌ | ❌ |
| Threat Intel Enrichment (VT/AbuseIPDB/OTX) | ✅ | ❌ | ❌ |
| Modern Web Dashboard | ✅ | ❌ | ❌ |
| Realtime Log Monitoring | ✅ | ❌ | ❌ |
| False Positive Suppression | ✅ | ❌ | ❌ |
| Training Mode for Analysts | ✅ | ❌ | ❌ |
| Multi-Format Export (JSON/CSV/STIX/PDF/DOCX) | ✅ | ❌ | ❌ |

---

## ✨ Key Features

### 🔍 Detection Power
- **115+ Built-in Detection Rules** — Advanced regex patterns for 25+ attack categories
- **SigmaHQ Integration** — Auto-sync and parse 3000+ Sigma rules with full condition support
- **YARA Scanning** — File, memory, and directory scanning
- **Behavioral Chain Detection** — 10 multi-stage attack patterns with time-window correlation
- **20 Correlation Rules** — Kill chain analysis and score boosting

### 🌐 Multi-Platform Parsers
- Windows EVTX & Sysmon
- Linux auditd
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
- APT Group Attribution (10 groups: APT28, APT29, Lazarus, etc.)
- CVE/NVD Feed with exploit checks
- Cached lookups with rate limiting

### 🎨 Modern Web UI
- Premium dark-themed cybersecurity aesthetic
- Interactive dashboards with severity charts
- Attack timeline visualization
- MITRE ATT&CK heatmap
- AI Copilot chat interface

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/0xsabry/ThreatScope.git
cd ThreatScope

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

# Analyze with JSON export
python cli.py analyze path/to/access.log -o report.json -f json

# Analyze with STIX 2.1 export
python cli.py analyze path/to/events.json -o stix_bundle.json -f stix

# Sync Sigma rules from SigmaHQ
python cli.py sync
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
```

---

## 📁 Project Structure

```
ThreatScope/
├── app.py                  # Flask web application
├── cli.py                  # Enhanced CLI interface
├── config.py               # Global configuration
├── requirements.txt        # Dependencies
├── core/
│   ├── analyzer.py         # Main analysis orchestrator
│   ├── sigma_engine.py     # Full Sigma rule parser
│   ├── sigma_sync.py       # SigmaHQ auto-sync
│   ├── behavioral_chain.py # Multi-stage attack detection
│   ├── yara_engine.py      # YARA scanning engine
│   ├── ioc_extractor.py    # IOC extraction engine
│   ├── correlation.py      # 20 correlation rules
│   ├── false_positive.py   # FP suppression engine
│   └── realtime_monitor.py # Live monitoring daemon
├── parsers/
│   └── log_parsers.py      # Multi-platform log parsers
├── intel/
│   ├── enrichment.py       # VT/AbuseIPDB/OTX enrichment
│   └── apt_mapper.py       # APT attribution & CVE feed
├── ai/
│   └── ai_core.py          # Narrative, Copilot, Training
├── export/
│   └── exporters.py        # JSON/CSV/STIX/PDF/DOCX
├── templates/              # Jinja2 HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── analysis.html
│   ├── timeline.html
│   ├── mitre.html
│   ├── intel.html
│   ├── copilot.html
│   ├── rules.html
│   └── settings.html
└── static/
    ├── css/style.css       # Premium dark theme
    └── js/app.js           # Frontend logic
```

---

## 🎯 MITRE ATT&CK Coverage

ThreatScope V2 maps findings to 40+ MITRE ATT&CK techniques and provides:
- Interactive heatmap visualization
- APT group attribution
- Kill chain coverage analysis
- Technique-to-tactic mapping

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

## 🛡️ Built-in Detection Categories

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
