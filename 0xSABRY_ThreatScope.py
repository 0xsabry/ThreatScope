import re
import json
import struct
import threading
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict
from urllib.parse import urlparse

# ================= EVTX OPTIONAL SUPPORT =================
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    EVTX_LIB = True
except ImportError:
    EVTX_LIB = False

VERSION = "2.0.0"

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

# Detection patterns, MITRE mapping, correlation rules, IOC patterns
# ... (written by builder)

# ================= EXTENDED DETECTION PATTERNS (75+ Rules) =================
PATTERNS = {
    # === Authentication & Access (T1078, T1110) ===
    "failed_login":              {"patterns": [r"EventID[=: ]*4625", r"failed (password|login|auth)", r"authentication failure", r"invalid (credentials|password|user)"], "severity": "MEDIUM", "weight": 5,  "category": "Authentication", "desc": "Failed login attempt detected", "mitre": "T1110"},
    "successful_login":          {"patterns": [r"EventID[=: ]*4624"], "severity": "INFO", "weight": 1, "category": "Authentication", "desc": "Successful logon event", "mitre": "T1078"},
    "anonymous_logon":           {"patterns": [r"ANONYMOUS LOGON", r"ANONYMOUS_LOGON"], "severity": "HIGH", "weight": 20, "category": "Authentication", "desc": "Anonymous logon detected - possible unauthenticated access", "mitre": "T1078.001"},
    "brute_force":               {"patterns": [r"too many (failed|invalid|auth)", r"account locked", r"EventID[=: ]*4740"], "severity": "HIGH", "weight": 25, "category": "Authentication", "desc": "Brute-force or account lockout indicator", "mitre": "T1110.001"},
    "password_spray":            {"patterns": [r"EventID[=: ]*4648", r"explicit credentials"], "severity": "HIGH", "weight": 20, "category": "Authentication", "desc": "Explicit credential use - possible password spray", "mitre": "T1110.003"},
    "default_credentials":       {"patterns": [r"admin:admin|root:root|admin:password|guest:guest"], "severity": "CRITICAL", "weight": 30, "category": "Authentication", "desc": "Default credentials used", "mitre": "T1078.001"},
    "account_creation":          {"patterns": [r"EventID[=: ]*4720", r"user account (was )?created", r"net user.*/add"], "severity": "MEDIUM", "weight": 15, "category": "Authentication", "desc": "New user account created", "mitre": "T1136.001"},
    "password_change":           {"patterns": [r"EventID[=: ]*4723|EventID[=: ]*4724", r"password (was )?(changed|reset)"], "severity": "MEDIUM", "weight": 10, "category": "Authentication", "desc": "Account password changed or reset", "mitre": "T1098"},
    "logon_type_anomaly":        {"patterns": [r"Logon Type:\s*(3|10|8)", r"LogonType[=: ]*(3|10|8)"], "severity": "MEDIUM", "weight": 10, "category": "Authentication", "desc": "Suspicious logon type (Network/RemoteInteractive/NetworkCleartext)", "mitre": "T1021"},
    "service_account_abuse":     {"patterns": [r"service account.*login|svc_.*logon", r"Logon Type:\s*5.*elevated"], "severity": "HIGH", "weight": 25, "category": "Authentication", "desc": "Service account anomalous usage", "mitre": "T1078.002"},

    # === Privilege & Escalation (T1068, T1548) ===
    "privilege_escalation":      {"patterns": [r"EventID[=: ]*4672", r"SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege"], "severity": "HIGH", "weight": 30, "category": "Privilege Escalation", "desc": "Special privileges assigned to new logon", "mitre": "T1134"},
    "token_manipulation":        {"patterns": [r"EventID[=: ]*4703|EventID[=: ]*4674", r"token (impersonation|theft|manipulation)"], "severity": "HIGH", "weight": 30, "category": "Privilege Escalation", "desc": "Token privilege manipulation detected", "mitre": "T1134.001"},
    "uac_bypass":                {"patterns": [r"uac.*bypass|bypass.*uac", r"eventvwr|fodhelper|sdclt"], "severity": "CRITICAL", "weight": 40, "category": "Privilege Escalation", "desc": "UAC bypass technique detected", "mitre": "T1548.002"},
    "sudo_abuse":                {"patterns": [r"sudo.*-s|sudo.*-i|sudo su", r"NOPASSWD"], "severity": "HIGH", "weight": 25, "category": "Privilege Escalation", "desc": "Suspicious sudo usage", "mitre": "T1548.003"},
    "named_pipe_impersonation":  {"patterns": [r"ImpersonateNamedPipeClient|named.?pipe.*impersonat", r"pipe.*privilege"], "severity": "HIGH", "weight": 30, "category": "Privilege Escalation", "desc": "Named pipe impersonation for privilege escalation", "mitre": "T1134.001"},
    "dll_search_order_hijack":   {"patterns": [r"dll.*search.*order|dll.*plant|side.?load.*dll", r"SetDllDirectory.*null"], "severity": "HIGH", "weight": 30, "category": "Privilege Escalation", "desc": "DLL search order hijacking attempt", "mitre": "T1574.001"},
    "seimpersonate_abuse":       {"patterns": [r"SeImpersonatePrivilege|SeAssignPrimaryToken", r"potato.*exploit|juicy.*potato|print.*spoofer"], "severity": "CRITICAL", "weight": 40, "category": "Privilege Escalation", "desc": "SeImpersonate privilege abuse (Potato exploit)", "mitre": "T1134.001"},

    # === Persistence (T1053, T1543, T1547) ===
    "persistence":               {"patterns": [r"EventID[=: ]*7045", r"new service (created|installed)"], "severity": "HIGH", "weight": 25, "category": "Persistence", "desc": "New service created - possible persistence mechanism", "mitre": "T1543.003"},
    "scheduled_task":            {"patterns": [r"EventID[=: ]*4698|EventID[=: ]*4702", r"schtasks.*create|at\.exe"], "severity": "HIGH", "weight": 25, "category": "Persistence", "desc": "Scheduled task created or modified", "mitre": "T1053.005"},
    "registry_persistence":      {"patterns": [r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", r"HKLM.*Run.*", r"reg (add|query).*Run"], "severity": "HIGH", "weight": 25, "category": "Persistence", "desc": "Registry run-key modification - persistence indicator", "mitre": "T1547.001"},
    "startup_modification":      {"patterns": [r"\\Startup\\", r"\\Start Menu\\Programs\\Startup"], "severity": "MEDIUM", "weight": 20, "category": "Persistence", "desc": "Startup folder modification detected", "mitre": "T1547.001"},
    "dll_hijacking":             {"patterns": [r"dll (hijack|side.?load|injection)", r"LoadLibrary.*\.dll"], "severity": "CRITICAL", "weight": 35, "category": "Persistence", "desc": "DLL hijacking or side-loading attempt", "mitre": "T1574.001"},
    "bootkit":                   {"patterns": [r"MBR (modif|write|overwrite|tamper)", r"bootkitty|bootsector"], "severity": "CRITICAL", "weight": 50, "category": "Persistence", "desc": "Bootkit or MBR modification detected", "mitre": "T1542.003"},
    "wmi_persistence":           {"patterns": [r"EventID[=: ]*5861", r"__EventFilter|__EventConsumer|CommandLineEventConsumer", r"wmi.*subscription.*persist"], "severity": "CRITICAL", "weight": 40, "category": "Persistence", "desc": "WMI event subscription persistence", "mitre": "T1546.003"},
    "bits_job_persistence":      {"patterns": [r"bitsadmin.*\/SetNotifyCmdLine|bits.*persist", r"Start-BitsTransfer.*-Asynchronous"], "severity": "HIGH", "weight": 25, "category": "Persistence", "desc": "BITS job abused for persistence", "mitre": "T1197"},
    "com_hijacking":             {"patterns": [r"InprocServer32.*modified|COM.*hijack|CLSID.*redirect", r"reg.*InprocServer32"], "severity": "HIGH", "weight": 30, "category": "Persistence", "desc": "COM object hijacking for persistence", "mitre": "T1546.015"},
    "image_file_exec_options":   {"patterns": [r"Image File Execution Options|IFEO.*debugger", r"GlobalFlag.*0x200"], "severity": "CRITICAL", "weight": 35, "category": "Persistence", "desc": "Image File Execution Options debugger set - persistence/evasion", "mitre": "T1546.012"},

    # === Lateral Movement (T1021, T1570) ===
    "lateral_movement":          {"patterns": [r"\bpsexec\b", r"\bwmic\b.*/node", r"EventID[=: ]*4648", r"\bwinrm\b"], "severity": "HIGH", "weight": 35, "category": "Lateral Movement", "desc": "Lateral movement tools detected (PsExec/WMIC/WinRM)", "mitre": "T1021"},
    "pass_the_hash":             {"patterns": [r"pass.?the.?hash|pth attack", r"NTLM.*lateral|mimikatz"], "severity": "CRITICAL", "weight": 50, "category": "Lateral Movement", "desc": "Pass-the-Hash attack indicator", "mitre": "T1550.002"},
    "rdp_anomaly":               {"patterns": [r"EventID[=: ]*4778|EventID[=: ]*4779", r"TermService|Remote Desktop"], "severity": "MEDIUM", "weight": 15, "category": "Lateral Movement", "desc": "RDP session reconnected or disconnected", "mitre": "T1021.001"},
    "smb_anomaly":               {"patterns": [r"EventID[=: ]*5140|EventID[=: ]*5145", r"\\\\.*\\(ADMIN|C|IPC)\$", r"smb (exploit|relay|attack)"], "severity": "HIGH", "weight": 30, "category": "Lateral Movement", "desc": "Suspicious SMB share access or exploit attempt", "mitre": "T1021.002"},
    "dcom_lateral":              {"patterns": [r"DCOM.*lateral|MMC20\.Application|ShellBrowserWindow", r"dcomexec"], "severity": "HIGH", "weight": 30, "category": "Lateral Movement", "desc": "DCOM-based lateral movement detected", "mitre": "T1021.003"},
    "wmi_lateral":               {"patterns": [r"wmic.*/node:.*process call|Win32_Process.*Create.*remote", r"wmiexec"], "severity": "HIGH", "weight": 30, "category": "Lateral Movement", "desc": "WMI-based remote execution for lateral movement", "mitre": "T1047"},
    "ssh_lateral":               {"patterns": [r"ssh.*-i.*key|ssh.*@.*root|sshpass", r"paramiko.*connect"], "severity": "MEDIUM", "weight": 15, "category": "Lateral Movement", "desc": "SSH-based lateral movement detected", "mitre": "T1021.004"},
    "admin_share_access":        {"patterns": [r"net use.*ADMIN\$|net use.*C\$|net use.*IPC\$", r"Map.*admin.*share"], "severity": "HIGH", "weight": 25, "category": "Lateral Movement", "desc": "Administrative share access for lateral movement", "mitre": "T1021.002"},

    # === Command & Control (T1071, T1572) ===
    "command_and_control":       {"patterns": [r"\bcobalt\b|\bcobalt strike\b", r"\bmeterpreter\b", r"\bsliver\b", r"\bhavoc\b"], "severity": "CRITICAL", "weight": 50, "category": "C2", "desc": "Known C2 framework artifact detected", "mitre": "T1219"},
    "dns_tunneling":             {"patterns": [r"dns (tunnel|exfil|c2)|iodine|dnscat", r"TXT.*base64", r"long.*subdomain.*query"], "severity": "CRITICAL", "weight": 45, "category": "C2", "desc": "DNS tunneling or covert channel detected", "mitre": "T1071.004"},
    "beacon_pattern":            {"patterns": [r"periodic.*request|beacon interval|check.?in.*interval"], "severity": "HIGH", "weight": 40, "category": "C2", "desc": "Beaconing behavior detected", "mitre": "T1071.001"},
    "tor_usage":                 {"patterns": [r"\.onion|tor (browser|exit|relay|node)", r"9050|9051|9150"], "severity": "HIGH", "weight": 30, "category": "C2", "desc": "Tor network usage detected", "mitre": "T1090.003"},
    "reverse_shell":             {"patterns": [r"bash -i.*>&|nc.*-e|python.*socket.*connect|\/dev\/tcp\/"], "severity": "CRITICAL", "weight": 50, "category": "C2", "desc": "Reverse shell command detected", "mitre": "T1059"},
    "http_c2_pattern":           {"patterns": [r"POST.*\/beacon|POST.*\/submit\.php|POST.*\/gate\.php", r"User-Agent.*(MSIE 6|wget|curl).*(C2|callback)"], "severity": "CRITICAL", "weight": 45, "category": "C2", "desc": "HTTP-based C2 communication pattern detected", "mitre": "T1071.001"},
    "icmp_tunnel":               {"patterns": [r"icmp.*tunnel|ping.*tunnel|icmpsh|ptunnel", r"ICMP.*payload.*data"], "severity": "HIGH", "weight": 35, "category": "C2", "desc": "ICMP tunneling for covert C2 channel", "mitre": "T1095"},
    "domain_fronting":           {"patterns": [r"domain.*front|CDN.*proxy.*C2|cloudfront.*redirect", r"Host:.*mismatch.*SNI"], "severity": "CRITICAL", "weight": 40, "category": "C2", "desc": "Domain fronting for C2 evasion detected", "mitre": "T1090.004"},
    "fast_flux_dns":             {"patterns": [r"fast.?flux|rapid.*DNS.*change|multiple.*A.*record.*rotation"], "severity": "HIGH", "weight": 30, "category": "C2", "desc": "Fast-flux DNS technique detected", "mitre": "T1568.001"},

    # === Exfiltration (T1041, T1048) ===
    "data_exfiltration":         {"patterns": [r"curl.*-T|wget.*--post-file", r"exfil|data.?theft", r"large.*upload|upload.*\d{3,}MB"], "severity": "HIGH", "weight": 35, "category": "Exfiltration", "desc": "Data exfiltration attempt detected", "mitre": "T1041"},
    "clipboard_exfil":           {"patterns": [r"GetClipboardData|clipboard (dump|steal|monitor)"], "severity": "HIGH", "weight": 25, "category": "Exfiltration", "desc": "Clipboard data access for exfiltration", "mitre": "T1115"},
    "email_exfil":               {"patterns": [r"smtp.*attach|sendmail.*attachment", r"EventID[=: ]*4663.*\.pst"], "severity": "HIGH", "weight": 30, "category": "Exfiltration", "desc": "Email-based exfiltration pattern", "mitre": "T1048.002"},
    "dns_exfiltration":          {"patterns": [r"dns.*exfil|TXT.*encoded.*data|subdomain.*base64", r"nslookup.*data.*encode"], "severity": "CRITICAL", "weight": 40, "category": "Exfiltration", "desc": "DNS-based data exfiltration detected", "mitre": "T1048.003"},
    "steganography_exfil":       {"patterns": [r"steghide|stegano|openstego|data.*hidden.*image", r"LSB.*embed|pixel.*encode"], "severity": "HIGH", "weight": 30, "category": "Exfiltration", "desc": "Steganography-based exfiltration detected", "mitre": "T1027.003"},
    "cloud_storage_exfil":       {"patterns": [r"rclone.*sync|rclone.*copy|mega.*upload", r"dropbox.*upload|gdrive.*upload|aws s3 cp"], "severity": "HIGH", "weight": 30, "category": "Exfiltration", "desc": "Cloud storage used for data exfiltration", "mitre": "T1567.002"},

    # === Defense Evasion (T1070, T1055) ===
    "log_tampering":             {"patterns": [r"EventID[=: ]*1102", r"EventID[=: ]*104", r"wevtutil.*cl", r"Clear-EventLog"], "severity": "CRITICAL", "weight": 40, "category": "Defense Evasion", "desc": "Event log cleared - critical defense evasion indicator", "mitre": "T1070.001"},
    "process_injection":         {"patterns": [r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread", r"process (inject|hollow|doppel)", r"reflective dll"], "severity": "CRITICAL", "weight": 45, "category": "Defense Evasion", "desc": "Process injection technique detected", "mitre": "T1055"},
    "obfuscation":               {"patterns": [r"base64.*-enc|frombase64string", r"iex\s*\(|invoke.?expression", r"char\(\d+\)\+char\(\d+\)"], "severity": "HIGH", "weight": 30, "category": "Defense Evasion", "desc": "Command obfuscation detected (Base64/IEX)", "mitre": "T1027"},
    "amsi_bypass":               {"patterns": [r"amsi.*bypass|AmsiScanBuffer|AmsiInitFailed", r"[Rr]ef.*Assembly.*AMSI"], "severity": "CRITICAL", "weight": 40, "category": "Defense Evasion", "desc": "AMSI bypass attempt detected", "mitre": "T1562.001"},
    "av_tamper":                 {"patterns": [r"(disable|stop|kill).*(antivirus|defender|av|edr)", r"Set-MpPreference.*Disable"], "severity": "CRITICAL", "weight": 40, "category": "Defense Evasion", "desc": "Antivirus/EDR tampering detected", "mitre": "T1562.001"},
    "timestomp":                 {"patterns": [r"timestomp|file.*timestamp.*(modif|manip|alter)", r"SetFileTime"], "severity": "HIGH", "weight": 25, "category": "Defense Evasion", "desc": "Timestamp manipulation (timestomping) detected", "mitre": "T1070.006"},
    "etw_bypass":                {"patterns": [r"EtwEventWrite.*patch|ETW.*bypass|NtTraceControl", r"etw.*disable.*provider"], "severity": "CRITICAL", "weight": 40, "category": "Defense Evasion", "desc": "ETW (Event Tracing for Windows) bypass detected", "mitre": "T1562.006"},
    "alternate_data_stream":     {"patterns": [r"ADS.*stream|:.*\.exe|type.*>.*:.*stream", r"alternate.*data.*stream|NTFS.*stream"], "severity": "HIGH", "weight": 25, "category": "Defense Evasion", "desc": "Alternate Data Stream (ADS) used to hide data", "mitre": "T1564.004"},
    "binary_padding":            {"patterns": [r"binary.*pad|file.*inflate|append.*null.*bytes", r"signature.*evade.*size"], "severity": "MEDIUM", "weight": 15, "category": "Defense Evasion", "desc": "Binary padding to evade hash-based detection", "mitre": "T1027.001"},
    "disable_firewall":          {"patterns": [r"netsh.*advfirewall.*off|netsh.*firewall.*disable", r"Set-NetFirewallProfile.*-Enabled.*False|iptables.*-F"], "severity": "CRITICAL", "weight": 35, "category": "Defense Evasion", "desc": "Host firewall disabled", "mitre": "T1562.004"},

    # === Discovery & Reconnaissance (T1087, T1018) ===
    "network_scan":              {"patterns": [r"\bnmap\b|\bmassscan\b|\bzmap\b", r"port.?scan|host.?discover", r"SYN.*flood|ACK.*flood"], "severity": "MEDIUM", "weight": 15, "category": "Discovery", "desc": "Network scanning activity detected", "mitre": "T1046"},
    "ad_recon":                  {"patterns": [r"(BloodHound|SharpHound|ldapdomaindump)", r"Get-ADUser|Get-ADComputer|Get-ADGroup", r"LDAP.*search.*samaccountname"], "severity": "HIGH", "weight": 30, "category": "Discovery", "desc": "Active Directory reconnaissance detected", "mitre": "T1087.002"},
    "os_discovery":              {"patterns": [r"systeminfo|uname -a|cat /etc/os-release", r"winver|ver\b"], "severity": "LOW", "weight": 5, "category": "Discovery", "desc": "OS enumeration command detected", "mitre": "T1082"},
    "user_enumeration":          {"patterns": [r"net user\b|net localgroup|whoami /all|id\b", r"Get-LocalUser|enum.*user"], "severity": "LOW", "weight": 5, "category": "Discovery", "desc": "User and group enumeration detected", "mitre": "T1087.001"},
    "group_policy_discovery":    {"patterns": [r"gpresult|Get-GPO|Get-GPResultantSetOfPolicy", r"group.?policy.*enum"], "severity": "MEDIUM", "weight": 10, "category": "Discovery", "desc": "Group Policy discovery activity", "mitre": "T1615"},
    "security_software_discovery": {"patterns": [r"tasklist.*/svc.*security|Get-Process.*(defender|symantec|mcafee|kaspersky)", r"WMIC.*AntiVirusProduct"], "severity": "MEDIUM", "weight": 15, "category": "Discovery", "desc": "Security software enumeration detected", "mitre": "T1518.001"},
    "network_share_discovery":   {"patterns": [r"net share|net view|Get-SmbShare", r"smbclient.*-L|enum4linux"], "severity": "MEDIUM", "weight": 10, "category": "Discovery", "desc": "Network share enumeration detected", "mitre": "T1135"},

    # === Credential Access (T1003) ===
    "credential_dumping":        {"patterns": [r"\bmimikatz\b|\blsadump\b|\bsekurlsa\b", r"lsass.*(dump|access|procdump)", r"EventID[=: ]*4663.*lsass"], "severity": "CRITICAL", "weight": 50, "category": "Credential Access", "desc": "Credential dumping attempt (LSASS/Mimikatz)", "mitre": "T1003.001"},
    "dcsync_attack":             {"patterns": [r"DCSync|DRS.*Replication|GetNCChanges", r"lsadump::dcsync"], "severity": "CRITICAL", "weight": 55, "category": "Credential Access", "desc": "DCSync attack - replicating AD credentials", "mitre": "T1003.006"},
    "sam_dump":                  {"patterns": [r"reg save.*SAM|reg save.*SECURITY|reg save.*SYSTEM", r"secretsdump|samdump"], "severity": "CRITICAL", "weight": 45, "category": "Credential Access", "desc": "SAM database credential dump detected", "mitre": "T1003.002"},
    "ntds_dit_extraction":       {"patterns": [r"ntds\.dit|ntdsutil.*snapshot|vssadmin.*shadow.*ntds", r"esedbexport.*ntds"], "severity": "CRITICAL", "weight": 55, "category": "Credential Access", "desc": "NTDS.dit extraction for offline credential dump", "mitre": "T1003.003"},
    "password_file_access":      {"patterns": [r"cat.*/etc/(passwd|shadow)|type.*\.password|findstr.*password", r"credential.*file.*access"], "severity": "HIGH", "weight": 20, "category": "Credential Access", "desc": "Password file access detected", "mitre": "T1552.001"},

    # === Web Attacks (T1190) ===
    "sql_injection":             {"patterns": [r"union\s+select|OR\s+1=1|'; *DROP", r"SLEEP\(\d+\)|WAITFOR DELAY", r"xp_cmdshell|EXEC\s*\("], "severity": "HIGH", "weight": 15, "category": "Web Attack", "desc": "SQL Injection attempt detected", "mitre": "T1190"},
    "xss":                       {"patterns": [r"<script[^>]*>", r"javascript:", r"onerror\s*=|onload\s*=", r"alert\s*\(.*\)"], "severity": "MEDIUM", "weight": 10, "category": "Web Attack", "desc": "Cross-Site Scripting (XSS) attempt detected", "mitre": "T1189"},
    "directory_traversal":       {"patterns": [r"\.\./\.\./", r"%2e%2e%2f", r"\.\.\\\.\.\\" , r"/etc/passwd|/etc/shadow"], "severity": "HIGH", "weight": 15, "category": "Web Attack", "desc": "Directory traversal attack detected", "mitre": "T1083"},
    "lfi_rfi":                   {"patterns": [r"(file|php|data|expect)://", r"include.*http://", r"require.*\.\./"], "severity": "HIGH", "weight": 20, "category": "Web Attack", "desc": "Local/Remote File Inclusion attempt detected", "mitre": "T1190"},
    "command_injection":         {"patterns": [r";\s*(ls|cat|id|whoami|wget|curl)\b", r"\|\s*(bash|sh|cmd|powershell)", r"`(id|whoami|uname)`"], "severity": "CRITICAL", "weight": 35, "category": "Web Attack", "desc": "OS Command Injection attempt detected", "mitre": "T1059"},
    "ssrf":                      {"patterns": [r"url=http://169\.254|url=http://127\.", r"metadata\.internal|169\.254\.169\.254"], "severity": "HIGH", "weight": 25, "category": "Web Attack", "desc": "Server-Side Request Forgery (SSRF) attempt detected", "mitre": "T1190"},
    "xxe":                       {"patterns": [r"<!ENTITY.*SYSTEM|<!DOCTYPE.*ENTITY", r"file:///"], "severity": "HIGH", "weight": 25, "category": "Web Attack", "desc": "XML External Entity (XXE) injection detected", "mitre": "T1190"},
    "deserialization_attack":    {"patterns": [r"ysoserial|ObjectInputStream|readObject|unserialize\(", r"java\.lang\.Runtime.*exec"], "severity": "CRITICAL", "weight": 40, "category": "Web Attack", "desc": "Insecure deserialization attack detected", "mitre": "T1190"},
    "http_smuggling":            {"patterns": [r"Transfer-Encoding.*chunked.*Content-Length|CL.*TE.*smuggl", r"HTTP.*request.*smuggl"], "severity": "HIGH", "weight": 30, "category": "Web Attack", "desc": "HTTP request smuggling attempt detected", "mitre": "T1190"},
    "crlf_injection":            {"patterns": [r"%0d%0a|\\r\\n.*inject|HTTP.*header.*inject", r"CRLF.*inject"], "severity": "MEDIUM", "weight": 15, "category": "Web Attack", "desc": "CRLF injection attempt detected", "mitre": "T1190"},
    "open_redirect":             {"patterns": [r"redirect.*=.*http|next=.*http|url=.*http|return.*=.*http", r"open.*redirect.*vuln"], "severity": "MEDIUM", "weight": 10, "category": "Web Attack", "desc": "Open redirect vulnerability exploitation attempt", "mitre": "T1190"},

    # === Malware & Ransomware (T1486) ===
    "ransomware":                {"patterns": [r"(encrypt|ransom|locked)\.(txt|html|note)", r"YOUR_FILES_ARE_ENCRYPTED", r"\.locked$|\.crypt$|\.enc$"], "severity": "CRITICAL", "weight": 60, "category": "Malware", "desc": "Ransomware activity indicators detected", "mitre": "T1486"},
    "malware_download":          {"patterns": [r"powershell.*DownloadString|powershell.*DownloadFile", r"bitsadmin.*transfer", r"certutil.*-decode|certutil.*-urlcache"], "severity": "CRITICAL", "weight": 45, "category": "Malware", "desc": "Malware download mechanism detected", "mitre": "T1105"},
    "worm_behavior":             {"patterns": [r"mass.?send|self.?replicate|propagat", r"net use.*\\.*\\ADMIN\$.*copy"], "severity": "CRITICAL", "weight": 40, "category": "Malware", "desc": "Worm-like propagation behavior detected", "mitre": "T1080"},
    "fileless_malware":          {"patterns": [r"powershell.*-nop.*-w hidden|powershell.*-enc.*bypass", r"mshta.*vbscript|regsvr32.*\/s.*\/n.*\/u", r"wscript.*\/b|cscript.*\/b"], "severity": "CRITICAL", "weight": 50, "category": "Malware", "desc": "Fileless malware technique detected (LOLBins)", "mitre": "T1059.001"},
    "macro_malware":             {"patterns": [r"macro.*download|VBA.*shell|Auto_Open.*exec", r"\.docm|\.xlsm.*malicious|macro.*enabled.*payload"], "severity": "HIGH", "weight": 35, "category": "Malware", "desc": "Malicious macro document detected", "mitre": "T1204.002"},
    "webshell_detection":        {"patterns": [r"webshell|web.?shell|c99|r57|b374k", r"cmd\.php|eval\s*\(\s*\$_(GET|POST|REQUEST)", r"<%.*eval.*request"], "severity": "CRITICAL", "weight": 50, "category": "Malware", "desc": "Web shell detected on server", "mitre": "T1505.003"},
    "dropper_behavior":          {"patterns": [r"dropper|payload.*drop|stage[12].*download", r"Invoke-WebRequest.*-OutFile|iwr.*-o.*\.exe"], "severity": "CRITICAL", "weight": 40, "category": "Malware", "desc": "Malware dropper behavior detected", "mitre": "T1105"},

    # === NTLM / Kerberos (T1558) ===
    "ntlm_downgrade":            {"patterns": [r"NTLM[- ]?V1|NTLMv1", r"LM Hash"], "severity": "HIGH", "weight": 20, "category": "Auth Protocol Attack", "desc": "NTLM downgrade attack detected", "mitre": "T1557.001"},
    "kerberoasting":             {"patterns": [r"kerberoast|GetUserSPNs|TGS.*RC4|EventID[=: ]*4769.*RC4"], "severity": "CRITICAL", "weight": 45, "category": "Auth Protocol Attack", "desc": "Kerberoasting attack detected", "mitre": "T1558.003"},
    "golden_silver_ticket":      {"patterns": [r"golden ticket|silver ticket|forge.*TGT|EventID[=: ]*4768.*0x12"], "severity": "CRITICAL", "weight": 60, "category": "Auth Protocol Attack", "desc": "Golden/Silver Ticket Kerberos attack detected", "mitre": "T1558.001"},

    # === Cloud & Container (T1525, T1610) ===
    "cloud_metadata_abuse":      {"patterns": [r"169\.254\.169\.254|metadata\.google\.internal", r"iam/security-credentials|instance-identity/document"], "severity": "CRITICAL", "weight": 40, "category": "Cloud Attack", "desc": "Cloud metadata service abuse attempt", "mitre": "T1552.005"},
    "container_escape":          {"patterns": [r"docker.*privileged|--privileged", r"container.*escape|nsenter|cgroup.*escape"], "severity": "CRITICAL", "weight": 45, "category": "Cloud Attack", "desc": "Container escape attempt detected", "mitre": "T1611"},

    # === Supply Chain Attack (T1195) ===
    "dependency_confusion":      {"patterns": [r"dependency.*confusion|package.*hijack|typosquat.*package", r"npm.*install.*malicious|pip.*install.*backdoor"], "severity": "CRITICAL", "weight": 50, "category": "Supply Chain", "desc": "Dependency confusion or package hijacking detected", "mitre": "T1195.002"},
    "typosquatting_package":     {"patterns": [r"typosquat|similar.*package.*name|impersonat.*package", r"pypi.*typo|npm.*typo"], "severity": "HIGH", "weight": 30, "category": "Supply Chain", "desc": "Package typosquatting attempt detected", "mitre": "T1195.002"},
    "build_pipeline_compromise": {"patterns": [r"CI/CD.*compromis|build.*pipeline.*inject|jenkins.*exploit", r"github.*action.*malicious|gitlab.*runner.*abuse"], "severity": "CRITICAL", "weight": 50, "category": "Supply Chain", "desc": "Build pipeline or CI/CD compromise detected", "mitre": "T1195.002"},

    # === IoT / OT Attack (T0800) ===
    "scada_ics_abuse":           {"patterns": [r"SCADA|Modbus|DNP3|OPC DA|ICS.*attack", r"PLC.*(stop|start|reprogram|upload)", r"S7comm|EtherNet/IP"], "severity": "CRITICAL", "weight": 55, "category": "IoT/OT Attack", "desc": "SCADA/ICS protocol abuse detected", "mitre": "T0855"},
    "modbus_exploit":            {"patterns": [r"Modbus.*write.*coil|Modbus.*function.*code.*(5|6|15|16)", r"modbus.*brute|modbus.*scan"], "severity": "CRITICAL", "weight": 50, "category": "IoT/OT Attack", "desc": "Modbus protocol exploitation attempt", "mitre": "T0831"},
    "mqtt_anomaly":              {"patterns": [r"MQTT.*(inject|exploit|abuse)|mosquitto.*unauth", r"MQTT.*subscribe.*#|MQTT.*wildcard"], "severity": "HIGH", "weight": 30, "category": "IoT/OT Attack", "desc": "MQTT protocol anomaly detected", "mitre": "T0883"},

    # === Insider Threat ===
    "mass_file_access":          {"patterns": [r"mass.*file.*(access|read|copy)|bulk.*file.*operation", r"EventID[=: ]*4663.*Count.*[5-9]\d{2,}"], "severity": "HIGH", "weight": 30, "category": "Insider Threat", "desc": "Mass file access pattern detected - possible insider data collection", "mitre": "T1005"},
    "off_hours_access":          {"patterns": [r"(0[0-4]):\d{2}:\d{2}.*logon|after.?hours.*access", r"weekend.*login.*critical"], "severity": "MEDIUM", "weight": 15, "category": "Insider Threat", "desc": "Off-hours system access detected", "mitre": "T1078"},
    "bulk_download":             {"patterns": [r"bulk.*download|mass.*download|wget.*-r.*mirror", r"download.*(\d{3,})\s*(files|documents|records)"], "severity": "HIGH", "weight": 30, "category": "Insider Threat", "desc": "Bulk data download detected", "mitre": "T1530"},
    "usb_exfil":                 {"patterns": [r"USB.*mass.*storage|removable.*media.*write|EventID[=: ]*6416", r"USBSTOR.*insert"], "severity": "HIGH", "weight": 25, "category": "Insider Threat", "desc": "USB storage device used - potential data exfiltration via removable media", "mitre": "T1052.001"},

    # === Zero-Day / Exploit (T1203) ===
    "exploit_kit":               {"patterns": [r"exploit.?kit|RIG.*EK|Magnitude.*EK|Fallout.*EK", r"landing.*page.*redirect.*exploit"], "severity": "CRITICAL", "weight": 50, "category": "Zero-Day/Exploit", "desc": "Exploit kit activity detected", "mitre": "T1203"},
    "shellcode_detect":          {"patterns": [r"shellcode|NOP.*sled|\\x90{4,}|egg.*hunter", r"payload.*generate.*msfvenom"], "severity": "CRITICAL", "weight": 50, "category": "Zero-Day/Exploit", "desc": "Shellcode or payload generation detected", "mitre": "T1203"},
    "heap_spray":                {"patterns": [r"heap.*spray|spray.*heap|0x0c0c0c0c|0x41414141{4,}", r"javascript.*unescape.*spray"], "severity": "CRITICAL", "weight": 45, "category": "Zero-Day/Exploit", "desc": "Heap spray attack technique detected", "mitre": "T1203"},
    "rop_chain":                 {"patterns": [r"ROP.*chain|return.*oriented.*program|gadget.*chain", r"stack.*pivot|ret2libc"], "severity": "CRITICAL", "weight": 45, "category": "Zero-Day/Exploit", "desc": "ROP chain exploitation technique detected", "mitre": "T1203"},

    # === Email / Phishing (T1566) ===
    "phishing_url":              {"patterns": [r"phishing|phish.*url|credential.*harvest.*url", r"login.*fake|signin.*spoof|account.*verify.*link"], "severity": "HIGH", "weight": 25, "category": "Email/Phishing", "desc": "Phishing URL or campaign detected", "mitre": "T1566.002"},
    "macro_document":            {"patterns": [r"\.docm|\.xlsm|\.pptm|macro.*enabled", r"VBA.*AutoOpen|Document_Open|Workbook_Open"], "severity": "HIGH", "weight": 30, "category": "Email/Phishing", "desc": "Macro-enabled document delivery detected", "mitre": "T1566.001"},
    "spoofed_sender":            {"patterns": [r"spoof.*sender|forged.*from|SPF.*fail.*spoof", r"DMARC.*fail|DKIM.*mismatch"], "severity": "HIGH", "weight": 25, "category": "Email/Phishing", "desc": "Email sender spoofing detected", "mitre": "T1566.001"},
    "credential_harvest":        {"patterns": [r"credential.*harvest|fake.*login.*page|evilginx|gophish", r"modlishka|king.*phisher"], "severity": "CRITICAL", "weight": 40, "category": "Email/Phishing", "desc": "Credential harvesting infrastructure detected", "mitre": "T1566.003"},

    # === Cryptomining (T1496) ===
    "mining_pool":               {"patterns": [r"mining.*pool|stratum\+tcp|pool\.(minergate|hashvault|nanopool)", r"monero.*pool|bitcoin.*pool|crypto.*mine.*connect"], "severity": "HIGH", "weight": 25, "category": "Cryptomining", "desc": "Cryptocurrency mining pool connection detected", "mitre": "T1496"},
    "stratum_protocol":          {"patterns": [r"stratum.*subscribe|mining\.submit|mining\.authorize", r"eth_submitWork|eth_getWork"], "severity": "HIGH", "weight": 30, "category": "Cryptomining", "desc": "Stratum mining protocol communication detected", "mitre": "T1496"},
    "xmrig_detect":              {"patterns": [r"xmrig|xmr-stak|cpuminer|minerd\b", r"randomx.*init|cryptonight.*hash"], "severity": "HIGH", "weight": 30, "category": "Cryptomining", "desc": "Cryptocurrency miner executable detected (XMRig/CPUMiner)", "mitre": "T1496"},
}


# ================= MITRE ATT&CK TECHNIQUE DESCRIPTIONS =================
MITRE_DESCRIPTIONS = {
    "T1110": "Brute Force", "T1110.001": "Password Guessing", "T1110.003": "Password Spraying",
    "T1078": "Valid Accounts", "T1078.001": "Default Accounts", "T1078.002": "Domain Accounts",
    "T1136.001": "Create Local Account", "T1098": "Account Manipulation",
    "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol", "T1021.002": "SMB/Windows Admin Shares",
    "T1021.003": "Distributed COM", "T1021.004": "SSH",
    "T1134": "Access Token Manipulation", "T1134.001": "Token Impersonation/Theft",
    "T1548.002": "Bypass UAC", "T1548.003": "Sudo & Sudo Caching",
    "T1574.001": "DLL Search Order Hijacking",
    "T1543.003": "Windows Service", "T1053.005": "Scheduled Task",
    "T1547.001": "Registry Run Keys / Startup", "T1542.003": "Bootkit",
    "T1546.003": "WMI Event Subscription", "T1546.012": "Image File Execution Options Injection",
    "T1546.015": "COM Hijacking", "T1197": "BITS Jobs",
    "T1550.002": "Pass the Hash", "T1047": "WMI",
    "T1219": "Remote Access Software", "T1071.001": "Web Protocols", "T1071.004": "DNS",
    "T1090.003": "Multi-hop Proxy (Tor)", "T1090.004": "Domain Fronting",
    "T1059": "Command & Scripting Interpreter", "T1059.001": "PowerShell",
    "T1095": "Non-Application Layer Protocol", "T1568.001": "Fast Flux DNS",
    "T1041": "Exfiltration Over C2", "T1115": "Clipboard Data",
    "T1048.002": "Exfil Over Alt Protocol - SMTP", "T1048.003": "Exfil Over Alt Protocol - DNS",
    "T1027": "Obfuscated Files or Information", "T1027.001": "Binary Padding", "T1027.003": "Steganography",
    "T1567.002": "Exfil to Cloud Storage",
    "T1070.001": "Clear Windows Event Logs", "T1070.006": "Timestomp",
    "T1055": "Process Injection", "T1562.001": "Disable/Modify Tools", "T1562.004": "Disable Firewall",
    "T1562.006": "Indicator Blocking (ETW)", "T1564.004": "NTFS File Attributes (ADS)",
    "T1046": "Network Service Discovery", "T1087.001": "Local Account Discovery",
    "T1087.002": "Domain Account Discovery", "T1082": "System Information Discovery",
    "T1615": "Group Policy Discovery", "T1518.001": "Security Software Discovery", "T1135": "Network Share Discovery",
    "T1003.001": "LSASS Memory", "T1003.002": "SAM", "T1003.003": "NTDS",
    "T1003.006": "DCSync", "T1552.001": "Credentials In Files", "T1552.005": "Cloud Instance Metadata",
    "T1190": "Exploit Public-Facing Application", "T1189": "Drive-by Compromise", "T1083": "File & Directory Discovery",
    "T1486": "Data Encrypted for Impact (Ransomware)", "T1105": "Ingress Tool Transfer",
    "T1080": "Taint Shared Content", "T1204.002": "Malicious File", "T1505.003": "Web Shell",
    "T1557.001": "LLMNR/NBT-NS Poisoning", "T1558.001": "Golden Ticket", "T1558.003": "Kerberoasting",
    "T1611": "Escape to Host (Container)", "T1195.002": "Compromise Software Supply Chain",
    "T0855": "Unauthorized Command Message (ICS)", "T0831": "Manipulation of Control (ICS)", "T0883": "Change Program State (ICS)",
    "T1005": "Data from Local System", "T1530": "Data from Cloud Storage",
    "T1052.001": "Exfil Over USB", "T1203": "Exploitation for Client Execution",
    "T1566.001": "Spearphishing Attachment", "T1566.002": "Spearphishing Link", "T1566.003": "Spearphishing via Service",
    "T1496": "Resource Hijacking (Cryptomining)",
}

# ================= CORRELATION RULES =================
CORRELATION_RULES = [
    {"name": "Credential Compromise Chain", "requires": ["brute_force", "privilege_escalation"], "severity": "CRITICAL", "score_boost": 20, "desc": "Brute-force followed by privilege escalation — likely credential compromise leading to escalation"},
    {"name": "Full Kill Chain Detected", "requires": ["credential_dumping", "lateral_movement", "data_exfiltration"], "severity": "CRITICAL", "score_boost": 30, "desc": "Credential theft → lateral movement → data exfiltration — full attack kill chain"},
    {"name": "Ransomware Deployment Chain", "requires": ["lateral_movement", "av_tamper", "ransomware"], "severity": "CRITICAL", "score_boost": 25, "desc": "Lateral movement with AV disabling followed by ransomware — coordinated ransomware attack"},
    {"name": "Active C2 with Exfiltration", "requires": ["command_and_control", "data_exfiltration"], "severity": "CRITICAL", "score_boost": 20, "desc": "Active C2 channel combined with data exfiltration — ongoing data breach"},
    {"name": "Persistence + Defense Evasion", "requires": ["persistence", "log_tampering"], "severity": "CRITICAL", "score_boost": 15, "desc": "Persistence mechanism deployed with log clearing — adversary covering tracks"},
    {"name": "Insider Threat Indicators", "requires": ["off_hours_access", "bulk_download"], "severity": "HIGH", "score_boost": 15, "desc": "Off-hours access combined with bulk downloads — potential malicious insider activity"},
    {"name": "AD Compromise Chain", "requires": ["ad_recon", "kerberoasting", "golden_silver_ticket"], "severity": "CRITICAL", "score_boost": 30, "desc": "AD recon → Kerberoasting → Golden Ticket — full Active Directory compromise"},
    {"name": "Supply Chain + Persistence", "requires": ["dependency_confusion", "persistence"], "severity": "CRITICAL", "score_boost": 20, "desc": "Supply chain compromise with persistence — advanced persistent threat activity"},
    {"name": "Web Attack to Shell", "requires": ["sql_injection", "reverse_shell"], "severity": "CRITICAL", "score_boost": 20, "desc": "SQL injection leading to reverse shell — web application fully compromised"},
    {"name": "Phishing to Credential Dump", "requires": ["phishing_url", "credential_dumping"], "severity": "CRITICAL", "score_boost": 20, "desc": "Phishing campaign followed by credential dumping — social engineering attack chain"},
]

# ================= IOC EXTRACTION PATTERNS =================
IOC_PATTERNS = {
    "md5":    r"\b[a-fA-F0-9]{32}\b",
    "sha1":   r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "ipv4":   r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url":    r"https?://[^\s\"'<>]+",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|info|ru|cn|tk|top|cc|pw|biz|me|co|uk|de|fr)\b",
    "email":  r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
    "cve":    r"CVE-\d{4}-\d{4,7}",
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
        self.iocs = defaultdict(set)
        self.correlations = []
        self.mitre_hits = defaultdict(int)
        self.timeline = []

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

            # IOC extraction
            for ioc_type, pattern in IOC_PATTERNS.items():
                for match in re.findall(pattern, line):
                    if ioc_type == "ipv4":
                        # Skip common private/loopback IPs
                        if not match.startswith(("0.", "127.", "255.")):
                            self.iocs[ioc_type].add(match)
                    elif ioc_type in ("md5", "sha1", "sha256"):
                        # Avoid false positives — skip if all identical chars
                        if len(set(match)) > 4:
                            self.iocs[ioc_type].add(match)
                    else:
                        self.iocs[ioc_type].add(match)

            # Pattern detection
            for cat, info in PATTERNS.items():
                for p in info["patterns"]:
                    if re.search(p, line, re.IGNORECASE):
                        self.findings[cat].append((lineno, line.strip()))
                        # MITRE tracking
                        mitre_id = info.get("mitre", "")
                        if mitre_id:
                            self.mitre_hits[mitre_id] += 1
                        # Timeline entry
                        ts_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", line)
                        timestamp = ts_match.group() if ts_match else f"Line {lineno}"
                        self.timeline.append({
                            "time": timestamp,
                            "rule": cat,
                            "severity": info["severity"],
                            "category": info["category"],
                            "line": lineno,
                            "content": line.strip()[:120]
                        })
                        break

        # Run correlation engine
        self._run_correlations()

    def _run_correlations(self):
        for rule in CORRELATION_RULES:
            if all(r in self.findings for r in rule["requires"]):
                self.correlations.append(rule)

    def calculate_threat_score(self):
        score = 0
        for cat, findings_list in self.findings.items():
            weight = PATTERNS[cat]["weight"]
            count = len(findings_list)
            if count == 1:
                score += weight
            elif count <= 5:
                score += weight + (count - 1) * (weight * 0.3)
            else:
                score += weight + 4 * (weight * 0.3) + (count - 5) * (weight * 0.1)
        # Add correlation bonuses
        for corr in self.correlations:
            score += corr["score_boost"]
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
            "version": VERSION,
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
            "detection_rules_total": len(PATTERNS),
            "detection_rules_triggered": len(self.findings),
            "mitre_techniques_detected": [
                {"id": mid, "name": MITRE_DESCRIPTIONS.get(mid, ""), "hits": cnt}
                for mid, cnt in sorted(self.mitre_hits.items(), key=lambda x: -x[1])
            ],
            "correlations": [
                {"name": c["name"], "severity": c["severity"], "description": c["desc"]}
                for c in self.correlations
            ],
            "iocs": {k: sorted(list(v))[:100] for k, v in self.iocs.items() if v},
            "findings_summary": {k: {"count": len(v), "severity": PATTERNS[k]["severity"], "category": PATTERNS[k]["category"], "description": PATTERNS[k]["desc"], "mitre": PATTERNS[k].get("mitre", "")} for k, v in self.findings.items()},
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
        out.append(f"       0xSABRY ThreatScope v{VERSION} — Advanced Log Intelligence Engine")
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
        out.append(f"│  Threat Score   : {score}% [{bar}]")
        out.append(f"│  Threat Level   : ► {level} ◄")
        out.append(f"│  Unique IPs     : {len(self.ip_counter):,}")
        out.append(f"│  Unique Users   : {len(self.user_counter):,}")
        out.append(f"│  Event IDs      : {len(self.event_id_counter):,} distinct")
        out.append(f"│  Rules Loaded   : {len(PATTERNS)}")
        out.append(f"│  Rules Triggered: {len(self.findings)}")
        out.append(f"│  MITRE Techniques: {len(self.mitre_hits)}")
        out.append(f"│  IOCs Extracted : {sum(len(v) for v in self.iocs.values())}")
        out.append(f"│  Correlations   : {len(self.correlations)}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")

        # Correlations
        if self.correlations:
            out.append("┌─ ⚡ ATTACK CHAIN CORRELATIONS ─────────────────────────────────────┐")
            for corr in self.correlations:
                sev_icon = "🔴" if corr["severity"] == "CRITICAL" else "🟠"
                out.append(f"│  {sev_icon} [{corr['severity']}] {corr['name']}")
                out.append(f"│     {corr['desc']}")
                out.append(f"│     Signals: {', '.join(corr['requires'])}")
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
                    mitre_tag = f" [{info.get('mitre', '')}]" if info.get('mitre') else ""
                    out.append(f"│     {sev_icon} [{sev:<8}] {info['desc']}{mitre_tag}")
                    out.append(f"│              → Rule: {cat}  |  Hits: {len(findings_list)}")
                    for ln, content in findings_list[:3]:
                        snippet = content[:80] + "..." if len(content) > 80 else content
                        out.append(f"│              ↳ Line {ln}: {snippet}")
                    if len(findings_list) > 3:
                        out.append(f"│              ↳ ... and {len(findings_list) - 3} more occurrences")
            out.append("│")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")

        # IOCs
        total_iocs = sum(len(v) for v in self.iocs.values())
        if total_iocs:
            out.append("┌─ 🔎 INDICATORS OF COMPROMISE (IOCs) ──────────────────────────────┐")
            for ioc_type, values in sorted(self.iocs.items()):
                if values:
                    out.append(f"│  ▶ {ioc_type.upper()} ({len(values)} found)")
                    for v in sorted(values)[:10]:
                        out.append(f"│     • {v}")
                    if len(values) > 10:
                        out.append(f"│     ... and {len(values)-10} more")
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
                "4719": "System Audit Policy Changed", "4720": "User Account Created", "4723": "Password Change Attempt",
                "4740": "Account Locked Out", "4769": "Kerberos TGS Requested",
                "7045": "New Service Installed", "1102": "Audit Log Cleared", "104": "System Log Cleared",
                "4663": "Object Access Attempt", "4703": "Token Rights Adjusted", "5140": "Network Share Accessed",
                "4778": "RDP Session Reconnected", "4779": "RDP Session Disconnected",
                "5861": "WMI Event Subscription",
            }
            for eid, count in self.event_id_counter.most_common(15):
                desc = known_ids.get(eid, "")
                out.append(f"│  EventID {eid:<8} {count:>6}x   {desc}")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")

        # MITRE ATT&CK Summary
        if self.mitre_hits:
            out.append("┌─ 🎯 MITRE ATT&CK COVERAGE ─────────────────────────────────────────┐")
            for mid, cnt in sorted(self.mitre_hits.items(), key=lambda x: -x[1])[:20]:
                desc = MITRE_DESCRIPTIONS.get(mid, "Unknown")
                out.append(f"│  {mid:<14} {desc:<45} {cnt:>4} hits")
            out.append("└────────────────────────────────────────────────────────────────────┘")
            out.append("")

        # Recommendations
        out.append("┌─ RECOMMENDATIONS ──────────────────────────────────────────────────┐")
        recs = []
        if "log_tampering" in self.findings:
            recs.append("URGENT: Event logs were cleared — treat as active incident, isolate system immediately")
        if "credential_dumping" in self.findings or "dcsync_attack" in self.findings:
            recs.append("URGENT: Credential dumping detected — rotate ALL domain credentials immediately")
        if "ransomware" in self.findings:
            recs.append("CRITICAL: Ransomware indicators found — isolate affected systems, activate IR plan")
        if "golden_silver_ticket" in self.findings or "kerberoasting" in self.findings:
            recs.append("Reset krbtgt password twice; audit all service account SPNs")
        if "command_and_control" in self.findings or "reverse_shell" in self.findings:
            recs.append("Block identified C2 IPs/domains; check for persistence mechanisms")
        if "brute_force" in self.findings:
            recs.append("Enable account lockout policy; consider MFA; review source IPs")
        if "privilege_escalation" in self.findings or "uac_bypass" in self.findings:
            recs.append("Audit privileged accounts; apply principle of least privilege")
        if "persistence" in self.findings or "scheduled_task" in self.findings or "wmi_persistence" in self.findings:
            recs.append("Audit all scheduled tasks, services, WMI subscriptions, and run keys")
        if "sql_injection" in self.findings or "command_injection" in self.findings:
            recs.append("Patch web application; implement WAF; review code for injection flaws")
        if "webshell_detection" in self.findings:
            recs.append("URGENT: Web shell detected — scan all web-accessible directories, rebuild from clean source")
        if "fileless_malware" in self.findings or "amsi_bypass" in self.findings:
            recs.append("Enable PowerShell ScriptBlock logging; restrict PowerShell execution policy")
        if "container_escape" in self.findings:
            recs.append("Review container security: disable privileged mode, implement seccomp profiles")
        if any(c["name"] == "Full Kill Chain Detected" for c in self.correlations):
            recs.append("CRITICAL: Full attack kill chain detected — activate full incident response immediately")
        if "mining_pool" in self.findings or "xmrig_detect" in self.findings:
            recs.append("Cryptominer detected — scan for unauthorized processes, review resource usage")
        if "phishing_url" in self.findings or "credential_harvest" in self.findings:
            recs.append("Phishing campaign detected — alert users, block identified phishing domains")
        if "scada_ics_abuse" in self.findings:
            recs.append("URGENT: ICS/SCADA attack detected — isolate OT network, engage OT security team")
        if "ntds_dit_extraction" in self.findings:
            recs.append("URGENT: NTDS.dit extraction — assume full domain compromise, begin recovery")
        if "disable_firewall" in self.findings or "av_tamper" in self.findings:
            recs.append("Security controls disabled — re-enable, investigate scope of compromise")
        if not recs:
            recs.append("Continue monitoring; no critical actions required at this time")
        for r in recs:
            out.append(f"│  ► {r}")
        out.append("└────────────────────────────────────────────────────────────────────┘")
        out.append("")
        out.append(f"  Report by 0xSABRY ThreatScope v{VERSION}  |  {now}")
        out.append(f"  Detection Rules: {len(PATTERNS)}  |  Categories: {len(set(v['category'] for v in PATTERNS.values()))}")
        out.append("═" * 72)

        return "\n".join(out)
