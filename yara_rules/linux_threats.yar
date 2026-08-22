/*
    ThreatScope V3 — Linux Threats YARA Rules
    Author: 0xSABRY

    Detects Linux-specific malware: rootkits, crypto miners,
    backdoors, and ELF packing/obfuscation.
*/

rule Linux_Rootkit_Diamorphine {
    meta:
        description = "Detects Diamorphine Linux kernel rootkit"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1014"
    strings:
        $s1 = "diamorphine" ascii nocase
        $s2 = "module_hide" ascii
        $s3 = "is_invisible" ascii
        $s4 = "hacked_kill" ascii
        $s5 = "hacked_getdents" ascii
    condition:
        uint32(0) == 0x464C457F and 3 of them
}

rule Linux_Rootkit_Reptile {
    meta:
        description = "Detects Reptile Linux rootkit"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1014"
    strings:
        $s1 = "reptile" ascii nocase
        $s2 = "r3pt1l3" ascii
        $s3 = "khook" ascii
        $s4 = "hide_file" ascii
        $s5 = "hide_process" ascii
        $s6 = "hide_tcp4_port" ascii
    condition:
        uint32(0) == 0x464C457F and 3 of them
}

rule Linux_Rootkit_Jynx2 {
    meta:
        description = "Detects Jynx2 userland rootkit"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1014"
    strings:
        $s1 = "jynx2" ascii nocase
        $s2 = "ld_poison" ascii
        $s3 = "libselinux" ascii
        $s4 = "/proc/net/tcp" ascii
        $s5 = "accept" ascii
        $s6 = "LD_PRELOAD" ascii
    condition:
        uint32(0) == 0x464C457F and ($s2 or ($s6 and 2 of ($s3, $s4, $s5)))
}

rule Linux_Rootkit_Generic {
    meta:
        description = "Detects generic Linux rootkit indicators"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1014"
    strings:
        $s1 = "LD_PRELOAD" ascii
        $s2 = "/etc/ld.so.preload" ascii
        $s3 = "sys_call_table" ascii
        $s4 = "hide_pid" ascii
        $s5 = "hide_port" ascii
        $s6 = "rootkit" ascii nocase
        $hook1 = "getdents" ascii
        $hook2 = "readdir" ascii
        $hook3 = "recvmsg" ascii
    condition:
        uint32(0) == 0x464C457F and (
            ($s1 and $s2) or
            ($s3 and 1 of ($hook*)) or
            ($s6 and 2 of ($s4, $s5, $hook1, $hook2))
        )
}

rule CryptoMiner_XMRig {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        author = "0xSABRY"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "xmrig" ascii wide nocase
        $s2 = "stratum+tcp://" ascii
        $s3 = "stratum+ssl://" ascii
        $s4 = "pool.minexmr" ascii
        $s5 = "supportxmr.com" ascii
        $s6 = "hashvault.pro" ascii
        $s7 = "moneroocean" ascii
        $s8 = "nanopool.org" ascii
        $cfg1 = "\"algo\":" ascii
        $cfg2 = "\"coin\":" ascii
        $cfg3 = "\"donate-level\":" ascii
        $cfg4 = "\"randomx\"" ascii
    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and (
            $s1 or
            2 of ($s2, $s3, $s4, $s5, $s6, $s7, $s8) or
            3 of ($cfg*)
        )
}

rule CryptoMiner_Generic {
    meta:
        description = "Detects generic cryptocurrency mining indicators"
        author = "0xSABRY"
        severity = "medium"
        mitre = "T1496"
    strings:
        $pool1 = "stratum://" ascii
        $pool2 = "mining pool" ascii nocase
        $pool3 = "hashrate" ascii nocase
        $pool4 = "getwork" ascii
        $pool5 = "getblocktemplate" ascii
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $algo3 = "ethash" ascii nocase
        $algo4 = "kawpow" ascii nocase
        $wallet = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and (
            2 of ($pool*) or
            ($wallet and 1 of ($algo*)) or
            (1 of ($pool*) and 1 of ($algo*))
        )
}

rule Linux_Backdoor_BPFDoor {
    meta:
        description = "Detects BPFDoor Linux backdoor"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1205"
    strings:
        $s1 = "hald-addon-acpi" ascii
        $s2 = "/dev/shm/kdmtmpflush" ascii
        $s3 = "SO_ATTACH_FILTER" ascii
        $s4 = "BPF_STMT" ascii
        $s5 = "/var/run/haldrund.pid" ascii
        $magic = { 21 7E 51 44 }
    condition:
        uint32(0) == 0x464C457F and (3 of ($s*) or $magic)
}

rule Linux_Backdoor_Symbiote {
    meta:
        description = "Detects Symbiote Linux malware"
        author = "0xSABRY"
        severity = "critical"
        mitre = "T1014"
    strings:
        $s1 = "LD_PRELOAD" ascii
        $s2 = "fopen" ascii
        $s3 = "readdir" ascii
        $s4 = "pcap_loop" ascii
        $s5 = "/etc/ld.so.preload" ascii
        $s6 = "libcryptoutils" ascii
        $hidden = "/proc/net/tcp" ascii
    condition:
        uint32(0) == 0x464C457F and $s1 and $s5 and 2 of ($s2, $s3, $s4, $s6, $hidden)
}

rule ELF_Packed_UPX {
    meta:
        description = "Detects UPX-packed ELF binaries (suspicious in server context)"
        author = "0xSABRY"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "$Info: This file is packed with the UPX" ascii
    condition:
        uint32(0) == 0x464C457F and 1 of them
}

rule ELF_Suspicious_Strings {
    meta:
        description = "Detects ELF binaries with suspicious functionality combination"
        author = "0xSABRY"
        severity = "medium"
        mitre = "T1059.004"
    strings:
        $net1 = "socket" ascii
        $net2 = "connect" ascii
        $net3 = "bind" ascii
        $exec1 = "execve" ascii
        $exec2 = "/bin/sh" ascii
        $exec3 = "/bin/bash" ascii
        $hide1 = "unlink" ascii
        $hide2 = "ptrace" ascii
        $hide3 = "/proc/self" ascii
        $crypt = "encrypt" ascii nocase
    condition:
        uint32(0) == 0x464C457F and
        filesize < 1MB and
        2 of ($net*) and 1 of ($exec*) and 1 of ($hide*) and $crypt
}
