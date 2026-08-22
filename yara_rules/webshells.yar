/*
    ThreatScope V3 — Webshell YARA Rules
    Author: 0xSABRY

    Detects common webshells across PHP, ASP/ASPX, and JSP with
    obfuscation-aware patterns.
*/

rule PHP_Webshell_Generic {
    meta:
        description = "Detects generic PHP webshell patterns"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $eval3 = "preg_replace" ascii nocase
        $exec1 = "exec(" ascii nocase
        $exec2 = "system(" ascii nocase
        $exec3 = "passthru(" ascii nocase
        $exec4 = "shell_exec(" ascii nocase
        $exec5 = "popen(" ascii nocase
        $exec6 = "proc_open(" ascii nocase
        $b64 = "base64_decode(" ascii nocase
        $gz = "gzinflate(" ascii nocase
        $rot = "str_rot13(" ascii nocase
        $upload = "move_uploaded_file(" ascii nocase
        $input = "$_REQUEST" ascii nocase
        $input2 = "$_POST" ascii nocase
        $input3 = "$_GET" ascii nocase
    condition:
        filesize < 500KB and
        (($eval1 or $eval2) and ($b64 or $gz or $rot)) or
        (2 of ($exec*) and 1 of ($input*)) or
        ($upload and 1 of ($exec*))
}

rule PHP_Webshell_C99 {
    meta:
        description = "Detects C99 PHP webshell"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $s1 = "c99shell" ascii nocase
        $s2 = "c99_sess_put" ascii nocase
        $s3 = "c99sh_" ascii nocase
        $s4 = "phpinfo()" ascii
        $s5 = "Safe mode" ascii
        $s6 = "Open_basedir" ascii
    condition:
        filesize < 1MB and 2 of them
}

rule PHP_Webshell_WSO {
    meta:
        description = "Detects WSO (Web Shell by Orb) webshell"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $s1 = "WSO" ascii wide
        $s2 = "Web Shell" ascii wide nocase
        $s3 = "FilesMan" ascii wide
        $s4 = "auth_pass" ascii
        $s5 = "shell_exec" ascii
    condition:
        filesize < 500KB and 3 of them
}

rule PHP_Webshell_p0wny {
    meta:
        description = "Detects p0wny webshell"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $s1 = "p0wny" ascii nocase
        $s2 = "shell_exec" ascii
        $s3 = "featherlight" ascii
        $s4 = "uname -a" ascii
    condition:
        filesize < 200KB and 3 of them
}

rule PHP_Webshell_Obfuscated {
    meta:
        description = "Detects obfuscated PHP webshell patterns"
        author = "0xSABRY"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $obf1 = /\$\w+=\s*chr\(\d+\)\.chr\(\d+\)/ ascii
        $obf2 = /eval\s*\(\s*gzinflate\s*\(\s*base64_decode/ ascii nocase
        $obf3 = /\$\w+\s*=\s*str_replace\s*\([^)]+\)\s*;\s*\$\w+\s*\(/ ascii
        $obf4 = "create_function" ascii
        $obf5 = /\$\w+\s*=\s*"\\x/ ascii
        $obf6 = "preg_replace('/.*/'.'e'" ascii
    condition:
        filesize < 500KB and 2 of them
}

rule ASPX_Webshell {
    meta:
        description = "Detects ASP/ASPX webshell patterns"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $s1 = "Process.Start" ascii wide
        $s2 = "cmd.exe" ascii wide
        $s3 = "powershell" ascii wide nocase
        $s4 = "Request.Form" ascii wide
        $s5 = "Request.QueryString" ascii wide
        $s6 = "Server.MapPath" ascii wide
        $s7 = "Response.Write" ascii wide
        $exec1 = "ProcessStartInfo" ascii wide
        $exec2 = "System.Diagnostics" ascii wide
        $io = "System.IO" ascii wide
    condition:
        filesize < 500KB and ($exec1 or $exec2) and 2 of ($s*)
}

rule JSP_Webshell {
    meta:
        description = "Detects JSP webshell patterns"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $s1 = "Runtime.getRuntime().exec" ascii
        $s2 = "ProcessBuilder" ascii
        $s3 = "request.getParameter" ascii
        $s4 = "/bin/sh" ascii
        $s5 = "cmd /c" ascii wide
        $s6 = "getInputStream" ascii
        $s7 = "BufferedReader" ascii
    condition:
        filesize < 500KB and $s3 and ($s1 or $s2) and 1 of ($s4, $s5)
}
