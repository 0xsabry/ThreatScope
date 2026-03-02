import re
import json
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

# ================= EVTX OPTIONAL SUPPORT =================
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    EVTX_LIB = True
except ImportError:
    EVTX_LIB = False

# ================= COLORS & THEME =================
BG_DARK     = "#0d0d0d"
BG_PANEL    = "#111111"
BG_CARD     = "#1a1a1a"
BG_WIDGET   = "#222222"
ACCENT      = "#00cfff"
ACCENT2     = "#9b59b6"
GREEN       = "#00e676"
YELLOW      = "#ffeb3b"
ORANGE      = "#ff9800"
RED         = "#f44336"
CRITICAL    = "#ff1744"
TEXT_MAIN   = "#f5f5f5"
TEXT_DIM    = "#9e9e9e"
TEXT_ACCENT = "#00d4ff"
FONT_MONO   = ("Cascadia Code", 10) if True else ("Consolas", 10)
FONT_TITLE  = ("Segoe UI", 11, "bold")
FONT_BIG    = ("Segoe UI", 16, "bold")

# ================= EXTENDED DETECTION PATTERNS =================
PATTERNS = {
    # === Authentication & Access ===
    "failed_login":              {"patterns": [r"EventID[=: ]*4625", r"failed (password|login|auth)", r"authentication failure", r"invalid (credentials|password|user)"], "severity": "MEDIUM", "weight": 5,  "category": "Authentication", "desc": "Failed login attempt detected"},
    "successful_login":          {"patterns": [r"EventID[=: ]*4624"], "severity": "INFO", "weight": 1, "category": "Authentication", "desc": "Successful logon event"},
    "anonymous_logon":           {"patterns": [r"ANONYMOUS LOGON", r"ANONYMOUS_LOGON"], "severity": "HIGH", "weight": 20, "category": "Authentication", "desc": "Anonymous logon detected — possible unauthenticated access"},
    "brute_force":               {"patterns": [r"too many (failed|invalid|auth)", r"account locked", r"EventID[=: ]*4740"], "severity": "HIGH", "weight": 25, "category": "Authentication", "desc": "Brute-force or account lockout indicator"},
    "password_spray":            {"patterns": [r"EventID[=: ]*4648", r"explicit credentials"], "severity": "HIGH", "weight": 20, "category": "Authentication", "desc": "Pass-the-ticket or explicit credential use — possible password spray"},
    "default_credentials":       {"patterns": [r"admin:admin|root:root|admin:password|guest:guest"], "severity": "CRITICAL", "weight": 30, "category": "Authentication", "desc": "Default credentials used"},

    # === Privilege & Escalation ===
    "privilege_escalation":      {"patterns": [r"EventID[=: ]*4672", r"SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege"], "severity": "HIGH", "weight": 30, "category": "Privilege Escalation", "desc": "Special privileges assigned to new logon"},
    "token_manipulation":        {"patterns": [r"EventID[=: ]*4703|EventID[=: ]*4674", r"token (impersonation|theft|manipulation)"], "severity": "HIGH", "weight": 30, "category": "Privilege Escalation", "desc": "Token privilege manipulation detected"},
    "uac_bypass":                {"patterns": [r"uac.*bypass|bypass.*uac", r"eventvwr|fodhelper|sdclt"], "severity": "CRITICAL", "weight": 40, "category": "Privilege Escalation", "desc": "UAC bypass technique detected"},
    "sudo_abuse":                {"patterns": [r"sudo.*-s|sudo.*-i|sudo su", r"NOPASSWD"], "severity": "HIGH", "weight": 25, "category": "Privilege Escalation", "desc": "Suspicious sudo usage"},

    # === Persistence ===
    "persistence":               {"patterns": [r"EventID[=: ]*7045", r"new service (created|installed)"], "severity": "HIGH", "weight": 25, "category": "Persistence", "desc": "New service created — possible persistence mechanism"},
    "scheduled_task":            {"patterns": [r"EventID[=: ]*4698|EventID[=: ]*4702", r"schtasks.*create|at\.exe"], "severity": "HIGH", "weight": 25, "category": "Persistence", "desc": "Scheduled task created or modified"},
    "registry_persistence":      {"patterns": [r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", r"HKLM.*Run.*", r"reg (add|query).*Run"], "severity": "HIGH", "weight": 25, "category": "Persistence", "desc": "Registry run-key modification — persistence indicator"},
    "startup_modification":      {"patterns": [r"\\Startup\\", r"\\Start Menu\\Programs\\Startup"], "severity": "MEDIUM", "weight": 20, "category": "Persistence", "desc": "Startup folder modification detected"},
    "dll_hijacking":             {"patterns": [r"dll (hijack|side.?load|injection)", r"LoadLibrary.*\.dll"], "severity": "CRITICAL", "weight": 35, "category": "Persistence", "desc": "DLL hijacking or side-loading attempt"},
    "bootkit":                   {"patterns": [r"MBR (modif|write|overwrite|tamper)", r"bootkitty|bootsector"], "severity": "CRITICAL", "weight": 50, "category": "Persistence", "desc": "Bootkit or MBR modification detected"},

    # === Lateral Movement ===
    "lateral_movement":          {"patterns": [r"\bpsexec\b", r"\bwmic\b.*\/node", r"EventID[=: ]*4648", r"\bwinrm\b"], "severity": "HIGH", "weight": 35, "category": "Lateral Movement", "desc": "Lateral movement tools detected (PsExec/WMIC/WinRM)"},
    "pass_the_hash":             {"patterns": [r"pass.?the.?hash|pth attack", r"NTLM.*lateral|mimikatz"], "severity": "CRITICAL", "weight": 50, "category": "Lateral Movement", "desc": "Pass-the-Hash attack indicator"},
    "rdp_anomaly":               {"patterns": [r"EventID[=: ]*4778|EventID[=: ]*4779", r"TermService|Remote Desktop"], "severity": "MEDIUM", "weight": 15, "category": "Lateral Movement", "desc": "RDP session reconnected or disconnected"},
    "smb_anomaly":               {"patterns": [r"EventID[=: ]*5140|EventID[=: ]*5145", r"\\\\.*\\(ADMIN|C|IPC)\$", r"smb (exploit|relay|attack)"], "severity": "HIGH", "weight": 30, "category": "Lateral Movement", "desc": "Suspicious SMB share access or exploit attempt"},

    # === Command & Control ===
    "command_and_control":       {"patterns": [r"\bcobalt\b|\bcobalt strike\b", r"\bmeterpreter\b", r"\bsliver\b", r"\bhavoc\b"], "severity": "CRITICAL", "weight": 50, "category": "C2", "desc": "Known C2 framework artifact detected"},
    "dns_tunneling":             {"patterns": [r"dns (tunnel|exfil|c2)|iodine|dnscat", r"TXT.*base64", r"long.*subdomain.*query"], "severity": "CRITICAL", "weight": 45, "category": "C2", "desc": "DNS tunneling or covert channel detected"},
    "beacon_pattern":            {"patterns": [r"periodic.*request|beacon interval|check.?in.*interval"], "severity": "HIGH", "weight": 40, "category": "C2", "desc": "Beaconing behavior detected"},
    "tor_usage":                 {"patterns": [r"\.onion|tor (browser|exit|relay|node)", r"9050|9051|9150"], "severity": "HIGH", "weight": 30, "category": "C2", "desc": "Tor network usage detected"},
    "reverse_shell":             {"patterns": [r"bash -i.*>&|nc.*-e|python.*socket.*connect|\/dev\/tcp\/"], "severity": "CRITICAL", "weight": 50, "category": "C2", "desc": "Reverse shell command detected"},

    # === Exfiltration ===
    "data_exfiltration":         {"patterns": [r"curl.*-T|wget.*--post-file", r"exfil|data.?theft", r"large.*upload|upload.*\d{3,}MB"], "severity": "HIGH", "weight": 35, "category": "Exfiltration", "desc": "Data exfiltration attempt detected"},
    "clipboard_exfil":           {"patterns": [r"GetClipboardData|clipboard (dump|steal|monitor)"], "severity": "HIGH", "weight": 25, "category": "Exfiltration", "desc": "Clipboard data access for exfiltration"},
    "email_exfil":               {"patterns": [r"smtp.*attach|sendmail.*attachment", r"EventID[=: ]*4663.*\.pst"], "severity": "HIGH", "weight": 30, "category": "Exfiltration", "desc": "Email-based exfiltration pattern"},

    # === Defense Evasion ===
    "log_tampering":             {"patterns": [r"EventID[=: ]*1102", r"EventID[=: ]*104", r"wevtutil.*cl", r"Clear-EventLog"], "severity": "CRITICAL", "weight": 40, "category": "Defense Evasion", "desc": "Event log cleared — critical defense evasion indicator"},
    "process_injection":         {"patterns": [r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread", r"process (inject|hollow|doppel)", r"reflective dll"], "severity": "CRITICAL", "weight": 45, "category": "Defense Evasion", "desc": "Process injection technique detected"},
    "obfuscation":               {"patterns": [r"base64.*-enc|frombase64string", r"iex\s*\(|invoke.?expression", r"char\(\d+\)\+char\(\d+\)"], "severity": "HIGH", "weight": 30, "category": "Defense Evasion", "desc": "Command obfuscation detected (Base64/IEX)"},
    "amsi_bypass":               {"patterns": [r"amsi.*bypass|AmsiScanBuffer|AmsiInitFailed", r"[Rr]ef.*Assembly.*AMSI"], "severity": "CRITICAL", "weight": 40, "category": "Defense Evasion", "desc": "AMSI bypass attempt detected"},
    "av_tamper":                 {"patterns": [r"(disable|stop|kill).*(antivirus|defender|av|edr)", r"Set-MpPreference.*Disable"], "severity": "CRITICAL", "weight": 40, "category": "Defense Evasion", "desc": "Antivirus/EDR tampering detected"},
    "timestomp":                 {"patterns": [r"timestomp|file.*timestamp.*(modif|manip|alter)", r"SetFileTime"], "severity": "HIGH", "weight": 25, "category": "Defense Evasion", "desc": "Timestamp manipulation (timestomping) detected"},

    # === Discovery & Reconnaissance ===
    "network_scan":              {"patterns": [r"\bnmap\b|\bmassscan\b|\bzmap\b", r"port.?scan|host.?discover", r"SYN.*flood|ACK.*flood"], "severity": "MEDIUM", "weight": 15, "category": "Discovery", "desc": "Network scanning activity detected"},
    "ad_recon":                  {"patterns": [r"(BloodHound|SharpHound|ldapdomaindump)", r"Get-ADUser|Get-ADComputer|Get-ADGroup", r"LDAP.*search.*samaccountname"], "severity": "HIGH", "weight": 30, "category": "Discovery", "desc": "Active Directory reconnaissance detected"},
    "credential_dumping":        {"patterns": [r"\bmimikatz\b|\blsadump\b|\bsekurlsa\b", r"lsass.*(dump|access|procdump)", r"EventID[=: ]*4663.*lsass"], "severity": "CRITICAL", "weight": 50, "category": "Credential Access", "desc": "Credential dumping attempt (LSASS/Mimikatz)"},
    "os_discovery":              {"patterns": [r"systeminfo|uname -a|cat /etc/os-release", r"winver|ver\b"], "severity": "LOW", "weight": 5, "category": "Discovery", "desc": "OS enumeration command detected"},

    # === Web Attacks ===
    "sql_injection":             {"patterns": [r"union\s+select|OR\s+1=1|'; *DROP", r"SLEEP\(\d+\)|WAITFOR DELAY", r"xp_cmdshell|EXEC\s*\("], "severity": "HIGH", "weight": 15, "category": "Web Attack", "desc": "SQL Injection attempt detected"},
    "xss":                       {"patterns": [r"<script[^>]*>", r"javascript:", r"onerror\s*=|onload\s*=", r"alert\s*\(.*\)"], "severity": "MEDIUM", "weight": 10, "category": "Web Attack", "desc": "Cross-Site Scripting (XSS) attempt detected"},
    "directory_traversal":       {"patterns": [r"\.\./\.\./", r"%2e%2e%2f", r"\.\.\\\.\.\\", r"/etc/passwd|/etc/shadow"], "severity": "HIGH", "weight": 15, "category": "Web Attack", "desc": "Directory traversal attack detected"},
    "lfi_rfi":                   {"patterns": [r"(file|php|data|expect)://", r"include.*http://", r"require.*\.\./"], "severity": "HIGH", "weight": 20, "category": "Web Attack", "desc": "Local/Remote File Inclusion attempt detected"},
    "command_injection":         {"patterns": [r";\s*(ls|cat|id|whoami|wget|curl)\b", r"\|\s*(bash|sh|cmd|powershell)", r"`(id|whoami|uname)`"], "severity": "CRITICAL", "weight": 35, "category": "Web Attack", "desc": "OS Command Injection attempt detected"},
    "ssrf":                      {"patterns": [r"url=http://169\.254|url=http://127\.", r"metadata\.internal|169\.254\.169\.254"], "severity": "HIGH", "weight": 25, "category": "Web Attack", "desc": "Server-Side Request Forgery (SSRF) attempt detected"},
    "xxe":                       {"patterns": [r"<!ENTITY.*SYSTEM|<!DOCTYPE.*ENTITY", r"file:///"], "severity": "HIGH", "weight": 25, "category": "Web Attack", "desc": "XML External Entity (XXE) injection detected"},

    # === Malware & Ransomware ===
    "ransomware":                {"patterns": [r"(encrypt|ransom|locked)\.(txt|html|note)", r"YOUR_FILES_ARE_ENCRYPTED", r"\.locked$|\.crypt$|\.enc$"], "severity": "CRITICAL", "weight": 60, "category": "Malware", "desc": "Ransomware activity indicators detected"},
    "malware_download":          {"patterns": [r"powershell.*DownloadString|powershell.*DownloadFile", r"bitsadmin.*transfer", r"certutil.*-decode|certutil.*-urlcache"], "severity": "CRITICAL", "weight": 45, "category": "Malware", "desc": "Malware download mechanism detected"},
    "worm_behavior":             {"patterns": [r"mass.?send|self.?replicate|propagat", r"net use.*\\.*\\ADMIN\$.*copy"], "severity": "CRITICAL", "weight": 40, "category": "Malware", "desc": "Worm-like propagation behavior detected"},

    # === NTLM / Kerberos ===
    "ntlm_downgrade":            {"patterns": [r"NTLM[- ]?V1|NTLMv1", r"LM Hash"], "severity": "HIGH", "weight": 20, "category": "Auth Protocol Attack", "desc": "NTLM downgrade attack detected"},
    "kerberoasting":             {"patterns": [r"kerberoast|GetUserSPNs|TGS.*RC4|EventID[=: ]*4769.*RC4"], "severity": "CRITICAL", "weight": 45, "category": "Auth Protocol Attack", "desc": "Kerberoasting attack detected"},
    "golden_silver_ticket":      {"patterns": [r"golden ticket|silver ticket|forge.*TGT|EventID[=: ]*4768.*0x12"], "severity": "CRITICAL", "weight": 60, "category": "Auth Protocol Attack", "desc": "Golden/Silver Ticket Kerberos attack detected"},

    # === Cloud & Container ===
    "cloud_metadata_abuse":      {"patterns": [r"169\.254\.169\.254|metadata\.google\.internal", r"iam/security-credentials|instance-identity/document"], "severity": "CRITICAL", "weight": 40, "category": "Cloud Attack", "desc": "Cloud metadata service abuse attempt"},
    "container_escape":          {"patterns": [r"docker.*privileged|--privileged", r"container.*escape|nsenter|cgroup.*escape"], "severity": "CRITICAL", "weight": 45, "category": "Cloud Attack", "desc": "Container escape attempt detected"},
}

# ================= EVTX PARSER =================
def parse_evtx_native(filepath: Path):
    lines = []
    with open(filepath, "rb") as f:
        data = f.read()
    chunk_offset = 4096
    while chunk_offset < len(data) - 8:
        if data[chunk_offset:chunk_offset+8] != b'ElfChnk\x00':
            break
        chunk_data = data[chunk_offset:chunk_offset + 65536]
        rp = 0
        while rp < len(chunk_data) - 4:
            if chunk_data[rp:rp+4] == b'\x2a\x2a\x00\x00':
                try:
                    size = struct.unpack_from('<I', chunk_data, rp + 4)[0]
                    rec_id = struct.unpack_from('<Q', chunk_data, rp + 8)[0]
                    rec_data = chunk_data[rp:rp + size]
                    text = rec_data.decode("utf-16le", errors="ignore")
                    lines.append(f"RecordID:{rec_id} {text}")
                    rp += size
                except Exception:
                    rp += 1
            else:
                rp += 1
        chunk_offset += 65536
    return lines

def parse_evtx_lib(filepath: Path):
    lines = []
    try:
        with Evtx(str(filepath)) as log:
            for xml_str, _ in evtx_file_xml_view(log.get_file_header()):
                lines.append(xml_str)
    except Exception:
        return parse_evtx_native(filepath)
    return lines

# ================= CORE ANALYZER =================
class LogAnalyzer:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.lines = []
        self.findings = defaultdict(list)
        self.ip_counter = Counter()
        self.user_counter = Counter()
        self.event_id_counter = Counter()
        self.total_lines = 0
        self.is_evtx = self.filepath.suffix.lower() == ".evtx"
        self.start_time = None
        self.end_time = None

    def load(self):
        if self.is_evtx:
            self.lines = parse_evtx_lib(self.filepath) if EVTX_LIB else parse_evtx_native(self.filepath)
        else:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                self.lines = f.readlines()
        self.total_lines = len(self.lines)

    def analyze(self):
        for lineno, line in enumerate(self.lines, 1):
            if not isinstance(line, str):
                continue

            # IPs
            for ip in re.findall(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", line):
                self.ip_counter[ip] += 1

            # Usernames (common log patterns)
            for user in re.findall(r"(?:user|username|account)[=: ]+([a-zA-Z0-9_\-\.]+)", line, re.IGNORECASE):
                self.user_counter[user] += 1

            # Event IDs
            for eid in re.findall(r"EventID[=: ]+(\d+)", line, re.IGNORECASE):
                self.event_id_counter[eid] += 1

            # Timestamps (first/last)
            for ts in re.findall(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", line):
                if not self.start_time:
                    self.start_time = ts
                self.end_time = ts

            # Pattern detection
            for cat, info in PATTERNS.items():
                for p in info["patterns"]:
                    if re.search(p, line, re.IGNORECASE):
                        self.findings[cat].append((lineno, line.strip()))
                        break

    def calculate_threat_score(self):
        score = 0
        for cat, findings_list in self.findings.items():
            weight = PATTERNS[cat]["weight"]
            count = len(findings_list)
            # Diminishing returns for repeated same-type findings
            if count == 1:
                score += weight
            elif count <= 5:
                score += weight + (count - 1) * (weight * 0.3)
            else:
                score += weight + 4 * (weight * 0.3) + (count - 5) * (weight * 0.1)
        return min(int(score), 100)

    def get_threat_level(self, score):
        if score >= 80: return "CRITICAL", CRITICAL
        if score >= 60: return "HIGH", RED
        if score >= 40: return "MEDIUM", ORANGE
        if score >= 20: return "LOW", YELLOW
        return "MINIMAL", GREEN

    def get_top_ips(self, n=10):
        return self.ip_counter.most_common(n)

    def get_findings_by_category(self):
        grouped = defaultdict(list)
        for cat, findings_list in self.findings.items():
            grp = PATTERNS[cat]["category"]
            grouped[grp].append((cat, findings_list))
        return grouped

    def export_json(self, path):
        score = self.calculate_threat_score()
        level, _ = self.get_threat_level(score)
        data = {
            "tool": "0xSABRY ThreatScope",
            "generated": datetime.now().isoformat(),
            "file": str(self.filepath),
            "file_size_bytes": self.filepath.stat().st_size,
            "total_lines": self.total_lines,
            "log_start": self.start_time,
            "log_end": self.end_time,
            "unique_ips": len(self.ip_counter),
            "unique_users": len(self.user_counter),
            "threat_score": score,
            "threat_level": level,
            "top_ips": self.get_top_ips(10),
            "top_users": self.user_counter.most_common(10),
            "event_id_summary": self.event_id_counter.most_common(20),
            "findings_summary": {k: {"count": len(v), "severity": PATTERNS[k]["severity"], "category": PATTERNS[k]["category"], "description": PATTERNS[k]["desc"]} for k, v in self.findings.items()},
            "findings_detail": {k: [{"line": ln, "content": c} for ln, c in v[:50]] for k, v in self.findings.items()},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def generate_report(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        score = self.calculate_threat_score()
        level, _ = self.get_threat_level(score)

        bar = "█" * (score // 5) + "░" * (20 - score // 5)

        out = []
        out.append("═" * 72)
        out.append("       0xSABRY ThreatScope — Advanced Log Intelligence Engine")
        out.append(f"       Report Generated: {now}")
        out.append("═" * 72)
        out.append("")
        out.append("┌─ FILE INFORMATION ─────────────────────────────────────────────────┐")
        out.append(f"│  File    : {self.filepath.name}")
        out.append(f"│  Size    : {self.filepath.stat().st_size:,} bytes")
        out.append(f"│  Type    : {'EVTX (Windows Event Log)' if self.is_evtx else 'Text Log'}")
        out.append(f"│  Lines   : {self.total_lines:,}")
        if self.start_time:
            out.append(f"│  Period  : {self.start_time}  →  {self.end_time}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")
        out.append("┌─ THREAT ASSESSMENT ────────────────────────────────────────────────┐")
        out.append(f"│  Threat Score  : {score}% [{bar}]")
        out.append(f"│  Threat Level  : ► {level} ◄")
        out.append(f"│  Unique IPs    : {len(self.ip_counter):,}")
        out.append(f"│  Unique Users  : {len(self.user_counter):,}")
        out.append(f"│  Event IDs     : {len(self.event_id_counter):,} distinct")
        out.append(f"│  Detection Rules Triggered : {len(self.findings)}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")

        # Findings by category
        grouped = self.get_findings_by_category()
        if grouped:
            out.append("┌─ FINDINGS BY CATEGORY ─────────────────────────────────────────────┐")
            for grp, items in sorted(grouped.items()):
                out.append(f"│")
                out.append(f"│  ▶ {grp.upper()}")
                for cat, findings_list in items:
                    info = PATTERNS[cat]
                    sev = info["severity"]
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(sev, "⚪")
                    out.append(f"│     {sev_icon} [{sev:<8}] {info['desc']}")
                    out.append(f"│              → Rule: {cat}  |  Hits: {len(findings_list)}")
                    # Show first 3 examples
                    for ln, content in findings_list[:3]:
                        snippet = content[:80] + "..." if len(content) > 80 else content
                        out.append(f"│              ↳ Line {ln}: {snippet}")
                    if len(findings_list) > 3:
                        out.append(f"│              ↳ ... and {len(findings_list) - 3} more occurrences")
            out.append("│")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")

        # Top IPs
        if self.ip_counter:
            out.append("┌─ TOP IP ADDRESSES ─────────────────────────────────────────────────┐")
            for ip, count in self.get_top_ips(10):
                bar_ip = "▌" * min(count, 30)
                out.append(f"│  {ip:<18} {bar_ip:<32} ({count:,} hits)")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")

        # Top Users
        if self.user_counter:
            out.append("┌─ TOP USERNAMES ────────────────────────────────────────────────────┐")
            for user, count in self.user_counter.most_common(10):
                out.append(f"│  {user:<25} {count:>6} occurrences")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")

        # Top Event IDs
        if self.event_id_counter:
            out.append("┌─ TOP EVENT IDs ────────────────────────────────────────────────────┐")
            known_ids = {
                "4624": "Successful Logon", "4625": "Failed Logon", "4648": "Explicit Credential Logon",
                "4672": "Special Privileges Assigned", "4698": "Scheduled Task Created", "4702": "Scheduled Task Updated",
                "4719": "System Audit Policy Changed", "4740": "Account Locked Out", "4769": "Kerberos TGS Requested",
                "7045": "New Service Installed", "1102": "Audit Log Cleared", "104": "System Log Cleared",
                "4663": "Object Access Attempt", "4703": "Token Rights Adjusted", "5140": "Network Share Accessed",
            }
            for eid, count in self.event_id_counter.most_common(15):
                desc = known_ids.get(eid, "")
                out.append(f"│  EventID {eid:<8} {count:>6}x   {desc}")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")

        # Recommendations
        out.append("┌─ RECOMMENDATIONS ──────────────────────────────────────────────────┐")
        recs = []
        if "log_tampering" in self.findings:
            recs.append("URGENT: Event logs were cleared — treat as active incident, isolate system immediately")
        if "credential_dumping" in self.findings:
            recs.append("URGENT: LSASS/credential dumping detected — rotate all credentials immediately")
        if "ransomware" in self.findings:
            recs.append("CRITICAL: Ransomware indicators found — isolate affected systems immediately")
        if "golden_silver_ticket" in self.findings or "kerberoasting" in self.findings:
            recs.append("Reset krbtgt password twice; audit all service account SPNs")
        if "command_and_control" in self.findings or "reverse_shell" in self.findings:
            recs.append("Block identified C2 IPs/domains; check for persistence mechanisms")
        if "brute_force" in self.findings:
            recs.append("Enable account lockout policy; consider MFA; review source IPs")
        if "privilege_escalation" in self.findings or "uac_bypass" in self.findings:
            recs.append("Audit privileged accounts; apply principle of least privilege")
        if "persistence" in self.findings or "scheduled_task" in self.findings:
            recs.append("Audit all scheduled tasks, services, and run keys for unauthorized entries")
        if "sql_injection" in self.findings or "command_injection" in self.findings:
            recs.append("Patch web application; implement WAF; review application code for injection flaws")
        if not recs:
            recs.append("Continue monitoring; no critical actions required at this time")
        for r in recs:
            out.append(f"│  ► {r}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")
        out.append(f"  Report by 0xSABRY ThreatScope  |  {now}")
        out.append("═" * 72)

        return "\n".join(out)


# ================= GUI =================
class ThreatScopeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("0xSABRY ThreatScope")
        self.root.geometry("1200x780")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG_DARK)
        self.file_path = None
        self.analyzer = None
        self._build_ui()

    def _build_ui(self):
        # ── HEADER ─────────────────────────────────────────────────────────
        header = tk.Frame(self.root, bg="#111111", height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        tk.Label(header, text="⚡ 0xSABRY ThreatScope", fg=ACCENT, bg="#111111",
                 font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT, padx=20, pady=12)
        tk.Label(header, text="Advanced Log Intelligence Engine", fg=TEXT_DIM, bg="#111111",
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, pady=12)

        # Version badge

        # ── TOOLBAR ────────────────────────────────────────────────────────
        toolbar = tk.Frame(self.root, bg=BG_PANEL, pady=8)
        toolbar.pack(fill=tk.X)

        btn_style = {"font": ("Segoe UI", 10, "bold"), "relief": tk.FLAT, "cursor": "hand2",
                     "padx": 16, "pady": 6}

        self.btn_load = tk.Button(toolbar, text="📂  Load Log", bg=BG_WIDGET, fg=ACCENT,
                                  command=self.load_file, **btn_style)
        self.btn_load.pack(side=tk.LEFT, padx=(12,4))

        self.btn_analyze = tk.Button(toolbar, text="🔍  Analyze", bg="#1565c0", fg="white",
                                     disabledforeground="#90caf9", activebackground="#1976d2",
                                     command=self.start_analysis, state=tk.DISABLED, **btn_style)
        self.btn_analyze.config(highlightbackground="#1565c0")
        self.btn_analyze.pack(side=tk.LEFT, padx=4)

        self.btn_export = tk.Button(toolbar, text="💾  Export JSON", bg=BG_WIDGET, fg=GREEN,
                                    command=self.export_json, state=tk.DISABLED, **btn_style)
        self.btn_export.pack(side=tk.LEFT, padx=4)

        self.btn_clear = tk.Button(toolbar, text="🗑  Clear", bg=BG_WIDGET, fg=TEXT_DIM,
                                   command=self.clear_output, **btn_style)
        self.btn_clear.pack(side=tk.LEFT, padx=4)

        # File label
        self.file_label = tk.Label(toolbar, text="No file loaded", fg=TEXT_DIM, bg=BG_PANEL,
                                   font=("Segoe UI", 9))
        self.file_label.pack(side=tk.LEFT, padx=16)

        # Rules count badge
        tk.Label(toolbar, text=f"🛡  {len(PATTERNS)} Detection Rules", fg=YELLOW, bg=BG_PANEL,
                 font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT, padx=16)

        # ── STATS ROW ─────────────────────────────────────────────────────
        stats_row = tk.Frame(self.root, bg=BG_DARK)
        stats_row.pack(fill=tk.X, padx=12, pady=(8, 0))

        self.stat_labels = {}
        stats = [
            ("score",    "THREAT SCORE",   "0%",   RED),
            ("level",    "THREAT LEVEL",   "—",    TEXT_DIM),
            ("lines",    "LINES",          "0",    ACCENT),
            ("ips",      "UNIQUE IPs",     "0",    ACCENT),
            ("users",    "USERS",          "0",    ACCENT),
            ("findings", "FINDINGS",       "0",    YELLOW),
        ]
        for key, title, default, color in stats:
            card = tk.Frame(stats_row, bg=BG_CARD, padx=16, pady=10, relief=tk.FLAT)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
            tk.Label(card, text=title, fg=TEXT_DIM, bg=BG_CARD,
                     font=("Segoe UI", 8)).pack(anchor=tk.W)
            lbl = tk.Label(card, text=default, fg=color, bg=BG_CARD,
                           font=("Segoe UI", 14, "bold"))
            lbl.pack(anchor=tk.W)
            self.stat_labels[key] = lbl

        # ── PROGRESS ──────────────────────────────────────────────────────
        prog_frame = tk.Frame(self.root, bg=BG_DARK)
        prog_frame.pack(fill=tk.X, padx=12, pady=4)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Threat.Horizontal.TProgressbar",
                        troughcolor=BG_WIDGET, background=ACCENT,
                        darkcolor=ACCENT, lightcolor=ACCENT,
                        bordercolor=BG_WIDGET, thickness=4)

        self.progress = ttk.Progressbar(prog_frame, mode="indeterminate",
                                        style="Threat.Horizontal.TProgressbar", length=400)
        self.progress.pack(side=tk.LEFT)
        self.status_label = tk.Label(prog_frame, text="Ready", fg=TEXT_DIM, bg=BG_DARK,
                                     font=("Segoe UI", 9))
        self.status_label.pack(side=tk.LEFT, padx=10)

        # ── MAIN CONTENT ──────────────────────────────────────────────────
        content = tk.Frame(self.root, bg=BG_DARK)
        content.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 8))

        # Tabs
        tab_bar = tk.Frame(content, bg=BG_DARK)
        tab_bar.pack(fill=tk.X, side=tk.TOP)

        self.tab_frames = {}
        self.tab_buttons = {}
        tab_defs = [
            ("report",   "📋 Full Report"),
            ("findings", "🚨 Findings"),
            ("ips",      "🌐 IP Analysis"),
            ("raw",      "📄 Raw Log"),
        ]

        self.active_tab = tk.StringVar(value="report")
        for tab_id, tab_title in tab_defs:
            btn = tk.Button(tab_bar, text=tab_title,
                            font=("Segoe UI", 9, "bold"),
                            relief=tk.FLAT, padx=14, pady=6,
                            cursor="hand2",
                            command=lambda t=tab_id: self.switch_tab(t))
            btn.pack(side=tk.LEFT)
            self.tab_buttons[tab_id] = btn

        # Tab content area
        self.tab_area = tk.Frame(content, bg=BG_CARD)
        self.tab_area.pack(fill=tk.BOTH, expand=True)

        # Create text widgets for each tab
        text_opts = dict(bg=BG_CARD, fg=TEXT_MAIN, insertbackground="white",
                         selectbackground=ACCENT2, relief=tk.FLAT,
                         wrap=tk.NONE, padx=10, pady=10)

        for tab_id, _ in tab_defs:
            frame = tk.Frame(self.tab_area, bg=BG_CARD)
            self.tab_frames[tab_id] = frame

            # Scrollbars
            vsb = tk.Scrollbar(frame, bg=BG_WIDGET, troughcolor=BG_DARK,
                                activebackground=ACCENT, width=10)
            hsb = tk.Scrollbar(frame, orient=tk.HORIZONTAL, bg=BG_WIDGET,
                                troughcolor=BG_DARK, activebackground=ACCENT, width=8)

            txt = tk.Text(frame, yscrollcommand=vsb.set, xscrollcommand=hsb.set,
                          font=FONT_MONO, **text_opts)
            vsb.config(command=txt.yview)
            hsb.config(command=txt.xview)

            vsb.pack(side=tk.RIGHT, fill=tk.Y)
            hsb.pack(side=tk.BOTTOM, fill=tk.X)
            txt.pack(fill=tk.BOTH, expand=True)
            txt.config(state=tk.DISABLED)

            frame._text = txt

        # Colored tags (applied to report tab)
        rt = self.tab_frames["report"]._text
        rt.tag_configure("critical", foreground=CRITICAL, font=("Cascadia Code", 10, "bold"))
        rt.tag_configure("high",     foreground=RED)
        rt.tag_configure("medium",   foreground=ORANGE)
        rt.tag_configure("low",      foreground=YELLOW)
        rt.tag_configure("info",     foreground=GREEN)
        rt.tag_configure("header",   foreground=ACCENT, font=("Cascadia Code", 10, "bold"))
        rt.tag_configure("accent",   foreground=ACCENT2)
        rt.tag_configure("dim",      foreground=TEXT_DIM)

        self.switch_tab("report")

    def switch_tab(self, tab_id):
        self.active_tab.set(tab_id)
        for t, f in self.tab_frames.items():
            f.pack_forget()
        self.tab_frames[tab_id].pack(fill=tk.BOTH, expand=True)

        for t, btn in self.tab_buttons.items():
            if t == tab_id:
                btn.config(bg=ACCENT, fg=BG_DARK)
            else:
                btn.config(bg=BG_DARK, fg=TEXT_DIM)

    def _write(self, tab_id, text, tag=None):
        txt = self.tab_frames[tab_id]._text
        txt.config(state=tk.NORMAL)
        if tag:
            txt.insert(tk.END, text, tag)
        else:
            txt.insert(tk.END, text)
        txt.config(state=tk.DISABLED)

    def _clear_tab(self, tab_id):
        txt = self.tab_frames[tab_id]._text
        txt.config(state=tk.NORMAL)
        txt.delete("1.0", tk.END)
        txt.config(state=tk.DISABLED)

    def load_file(self):
        path = filedialog.askopenfilename(
            title="Load Log File",
            filetypes=[("All Supported", "*.log *.txt *.evtx"),
                       ("Log Files", "*.log"), ("Text Files", "*.txt"),
                       ("EVTX Files", "*.evtx"), ("All Files", "*.*")]
        )
        if path:
            self.file_path = path
            name = Path(path).name
            size = Path(path).stat().st_size
            size_str = f"{size:,} bytes" if size < 1024*1024 else f"{size/1024/1024:.1f} MB"
            self.file_label.config(text=f"📄 {name}  ({size_str})", fg=ACCENT)
            self.btn_analyze.config(state=tk.NORMAL, bg="#1565c0")
            self.set_status(f"Loaded: {name}")

    def start_analysis(self):
        if not self.file_path:
            return
        self.btn_analyze.config(state=tk.DISABLED, bg="#1565c0")
        self.btn_export.config(state=tk.DISABLED)
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def set_status(self, msg):
        self.status_label.config(text=msg)

    def run_analysis(self):
        self.root.after(0, lambda: self.progress.start(12))
        self.root.after(0, lambda: self.set_status("Loading file..."))

        try:
            a = LogAnalyzer(self.file_path)
            a.load()
            self.root.after(0, lambda: self.set_status(f"Analyzing {a.total_lines:,} lines..."))
            a.analyze()
            self.analyzer = a
            self.root.after(0, self._update_ui)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.set_status("Error during analysis"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.btn_analyze.config(state=tk.NORMAL, bg="#1565c0"))

    def _update_ui(self):
        a = self.analyzer
        score = a.calculate_threat_score()
        level, level_color = a.get_threat_level(score)

        # Stats row
        self.stat_labels["score"].config(text=f"{score}%", fg=level_color)
        self.stat_labels["level"].config(text=level, fg=level_color)
        self.stat_labels["lines"].config(text=f"{a.total_lines:,}", fg=ACCENT)
        self.stat_labels["ips"].config(text=f"{len(a.ip_counter):,}", fg=ACCENT)
        self.stat_labels["users"].config(text=f"{len(a.user_counter):,}", fg=ACCENT)
        self.stat_labels["findings"].config(text=f"{len(a.findings)}", fg=YELLOW)

        # ── Report tab ─────────────────────────────────────────────────────
        self._clear_tab("report")
        report = a.generate_report()
        lines = report.split("\n")
        for line in lines:
            tag = None
            if "CRITICAL" in line or "🔴" in line:    tag = "critical"
            elif "HIGH" in line or "🟠" in line:       tag = "high"
            elif "MEDIUM" in line or "🟡" in line:     tag = "medium"
            elif "LOW" in line or "🟢" in line:        tag = "low"
            elif "INFO" in line or "🔵" in line:       tag = "info"
            elif line.startswith("═") or line.startswith("┌") or line.startswith("└"):
                tag = "header"
            elif "URGENT" in line or "CRITICAL:" in line: tag = "critical"
            self._write("report", line + "\n", tag)

        # ── Findings tab ───────────────────────────────────────────────────
        self._clear_tab("findings")
        if a.findings:
            grouped = a.get_findings_by_category()
            for grp, items in sorted(grouped.items()):
                self._write("findings", f"\n{'━'*60}\n  ▶ {grp.upper()}\n{'━'*60}\n")
                for cat, flist in items:
                    info = PATTERNS[cat]
                    sev_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
                    icon = sev_colors.get(info["severity"], "⚪")
                    self._write("findings", f"\n{icon} [{info['severity']}] {info['desc']}\n")
                    self._write("findings", f"   Rule: {cat}  |  Hits: {len(flist)}\n")
                    for ln, content in flist[:10]:
                        self._write("findings", f"   Line {ln:>6}: {content[:100]}\n")
                    if len(flist) > 10:
                        self._write("findings", f"   ... {len(flist)-10} more hits\n")
        else:
            self._write("findings", "\n  ✅ No suspicious patterns detected.\n")

        # ── IP Analysis tab ────────────────────────────────────────────────
        self._clear_tab("ips")
        self._write("ips", f"\n  TOP IP ADDRESSES  (Total unique: {len(a.ip_counter):,})\n")
        self._write("ips", "  " + "─"*60 + "\n")
        if a.ip_counter:
            max_count = a.ip_counter.most_common(1)[0][1]
            for ip, cnt in a.ip_counter.most_common(50):
                bar_len = int((cnt / max_count) * 30)
                bar = "▌" * bar_len
                self._write("ips", f"  {ip:<20} {bar:<32} {cnt:>6} hits\n")
        else:
            self._write("ips", "\n  No IP addresses found.\n")

        # Top users
        if a.user_counter:
            self._write("ips", f"\n\n  TOP USERNAMES  (Total unique: {len(a.user_counter):,})\n")
            self._write("ips", "  " + "─"*60 + "\n")
            for user, cnt in a.user_counter.most_common(30):
                self._write("ips", f"  {user:<30} {cnt:>6} occurrences\n")

        # Top Event IDs
        if a.event_id_counter:
            self._write("ips", f"\n\n  TOP EVENT IDs\n")
            self._write("ips", "  " + "─"*60 + "\n")
            known_ids = {
                "4624":"Successful Logon","4625":"Failed Logon","4648":"Explicit Credential Logon",
                "4672":"Special Privileges","4698":"Sched Task Created","4702":"Sched Task Updated",
                "4719":"Audit Policy Changed","4740":"Account Locked Out","4769":"Kerberos TGS Req",
                "7045":"New Service","1102":"Audit Log Cleared","104":"System Log Cleared",
            }
            for eid, cnt in a.event_id_counter.most_common(20):
                desc = known_ids.get(eid, "")
                self._write("ips", f"  EventID {eid:<8} {cnt:>6}x   {desc}\n")

        # ── Raw Log tab ────────────────────────────────────────────────────
        self._clear_tab("raw")
        MAX_LINES = 2000
        for i, line in enumerate(a.lines[:MAX_LINES]):
            self._write("raw", f"{i+1:>6}  {line if isinstance(line, str) else repr(line)}")
        if a.total_lines > MAX_LINES:
            self._write("raw", f"\n... (showing first {MAX_LINES:,} of {a.total_lines:,} lines) ...")

        self.btn_export.config(state=tk.NORMAL)
        self.set_status(f"Analysis complete — {a.total_lines:,} lines, {len(a.findings)} findings, score: {score}%")
        self.switch_tab("report")

    def clear_output(self):
        for tab_id in self.tab_frames:
            self._clear_tab(tab_id)
        for key, lbl in self.stat_labels.items():
            lbl.config(text="0%" if key == "score" else "—" if key == "level" else "0", fg=TEXT_DIM)
        self.file_label.config(text="No file loaded", fg=TEXT_DIM)
        self.file_path = None
        self.analyzer = None
        self.btn_analyze.config(state=tk.DISABLED, bg="#1565c0")
        self.btn_export.config(state=tk.DISABLED)
        self.set_status("Ready")

    def export_json(self):
        if self.analyzer:
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json")],
                title="Export Report as JSON"
            )
            if path:
                self.analyzer.export_json(path)
                messagebox.showinfo("Export Done", f"Report saved to:\n{path}")


# ================= RUN =================
if __name__ == "__main__":
    root = tk.Tk()
    ThreatScopeGUI(root)
    root.mainloop()
