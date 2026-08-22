/*
    ThreatScope V3 — Suspicious Documents YARA Rules
    Author: 0xSABRY

    Detects malicious Office macros, PDF exploits, and weaponized
    document formats (ISO, IMG, LNK).
*/

rule Maldoc_VBA_AutoExec {
    meta:
        description = "Detects Office documents with auto-executing VBA macros"
        author = "0xSABRY"
        severity = "high"
        mitre = "T1204.002"
    strings:
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Auto_Open" ascii nocase
        $auto3 = "AutoExec" ascii nocase
        $auto4 = "Document_Open" ascii nocase
        $auto5 = "Workbook_Open" ascii nocase
        $auto6 = "AutoClose" ascii nocase
        $exec1 = "Shell" ascii nocase
        $exec2 = "WScript.Shell" ascii nocase
        $exec3 = "PowerShell" ascii nocase
        $exec4 = "cmd.exe" ascii nocase
        $exec5 = "CreateObject" ascii nocase
        $dl1 = "URLDownloadToFile" ascii nocase
        $dl2 = "XMLHTTP" ascii nocase
        $dl3 = "WinHttpRequest" ascii nocase
    condition:
        filesize < 10MB and 1 of ($auto*) and (1 of ($exec*) or 1 of ($dl*))
}

rule Maldoc_VBA_Obfuscated {
    meta:
        description = "Detects obfuscated VBA macro code"
        author = "0xSABRY"
        severity = "high"
        mitre = "T1027"
    strings:
        $chr = /Chr\(\d+\)\s*&\s*Chr\(\d+\)\s*&\s*Chr\(\d+\)/ ascii nocase
        $split = /Split\([^)]+,\s*"[^"]{1,3}"\)/ ascii nocase
        $env = "Environ(" ascii nocase
        $exec = "Shell " ascii nocase
        $long_str = /"\w{100,}"/ ascii
        $replace = /Replace\([^)]+,[^)]+,[^)]+\)/ ascii nocase
    condition:
        filesize < 10MB and 3 of them
}

rule Maldoc_Embedded_PE {
    meta:
        description = "Detects PE executable embedded in document"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1204.002"
    strings:
        $mz = { 4D 5A 90 00 }
        $pe = "This program cannot be run in DOS mode" ascii
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $pkzip = { 50 4B 03 04 }
    condition:
        ($ole at 0 or $pkzip at 0) and ($mz or $pe)
}

rule PDF_JavaScript {
    meta:
        description = "Detects PDF with embedded JavaScript execution"
        author = "0xSABRY"
        severity = "high"
        mitre = "T1204.002"
    strings:
        $pdf = "%PDF" ascii
        $js1 = "/JavaScript" ascii
        $js2 = "/JS " ascii
        $js3 = "/OpenAction" ascii
        $js4 = "/AA" ascii
        $launch = "/Launch" ascii
        $uri = "/URI" ascii
        $embedded = "/EmbeddedFile" ascii
        $exploit1 = "util.printf" ascii
        $exploit2 = "app.doc" ascii
        $exploit3 = "Collab.getIcon" ascii
    condition:
        $pdf at 0 and (
            ($js1 and ($js3 or $js4)) or
            ($launch and $uri) or
            2 of ($exploit*)
        )
}

rule PDF_Embedded_File {
    meta:
        description = "Detects PDF with embedded files (potential payload delivery)"
        author = "0xSABRY"
        severity = "medium"
        mitre = "T1204.002"
    strings:
        $pdf = "%PDF" ascii
        $ef = "/EmbeddedFiles" ascii
        $filespec = "/Filespec" ascii
        $stream = "/FlateDecode" ascii
        $exe = ".exe" ascii nocase
        $dll = ".dll" ascii nocase
        $scr = ".scr" ascii nocase
        $bat = ".bat" ascii nocase
        $ps1 = ".ps1" ascii nocase
    condition:
        $pdf at 0 and $ef and $filespec and 1 of ($exe, $dll, $scr, $bat, $ps1)
}

rule ISO_IMG_Container {
    meta:
        description = "Detects ISO/IMG containers with executable content"
        author = "0xSABRY"
        severity = "high"
        mitre = "T1553.005"
    strings:
        $iso_magic = "CD001" ascii
        $exe = ".exe" ascii nocase
        $dll = ".dll" ascii nocase
        $lnk = ".lnk" ascii nocase
        $bat = ".bat" ascii nocase
        $cmd = ".cmd" ascii nocase
        $ps1 = ".ps1" ascii nocase
        $vbs = ".vbs" ascii nocase
        $mz = { 4D 5A }
    condition:
        $iso_magic and ($mz or 2 of ($exe, $dll, $lnk, $bat, $cmd, $ps1, $vbs))
}

rule LNK_Suspicious {
    meta:
        description = "Detects suspicious LNK shortcut files with command execution"
        author = "0xSABRY"
        severity = "high"
        mitre = "T1204.002"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $cmd = "cmd" ascii wide nocase
        $ps = "powershell" ascii wide nocase
        $mshta = "mshta" ascii wide nocase
        $wscript = "wscript" ascii wide nocase
        $cscript = "cscript" ascii wide nocase
        $rundll = "rundll32" ascii wide nocase
        $certutil = "certutil" ascii wide nocase
        $bitsadmin = "bitsadmin" ascii wide nocase
    condition:
        $lnk_magic at 0 and 1 of ($cmd, $ps, $mshta, $wscript, $cscript, $rundll, $certutil, $bitsadmin)
}
