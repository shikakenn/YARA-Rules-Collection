rule Windows_Trojan_Bughatch_21269be4 {
    meta:
        id = "5mgkCvtVl21hneyuE4w1KV"
        fingerprint = "v1_sha256_a8a2cae51a31e48ffe729df61ec96e3257f9c997ad5234075f85ed55de96f11d"
        version = "1.0"
        date = "2022-05-09"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/bughatch-malware-analysis"
        threat_name = "Windows.Trojan.Bughatch"
        reference_sample = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 8B 45 ?? 33 D2 B9 A7 00 00 00 F7 F1 85 D2 75 ?? B8 01 00 00 00 EB 33 C0 }
        $a2 = { 8B 45 ?? 0F B7 48 04 81 F9 64 86 00 00 75 3B 8B 55 ?? 0F B7 42 16 25 00 20 00 00 ?? ?? B8 06 00 00 00 EB ?? }
        $b1 = { 69 4D 10 FD 43 03 00 81 C1 C3 9E 26 00 89 4D 10 8B 55 FC 8B 45 F8 0F B7 0C 50 8B 55 10 C1 EA 10 81 E2 FF FF 00 00 33 CA 8B 45 FC 8B 55 F8 66 89 0C 42 }
    condition:
        any of them
}

rule Windows_Trojan_Bughatch_98f3c0be {
    meta:
        id = "2NBIsC5NQVzJPwbtFUTXCM"
        fingerprint = "v1_sha256_d578515fece7bd464bb09cc5ddb5caf70f4022e8b10388db689e67e662d57f66"
        version = "1.0"
        date = "2022-05-09"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/bughatch-malware-analysis"
        threat_name = "Windows.Trojan.Bughatch"
        reference_sample = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "-windowstyle hidden -executionpolicy bypass -file"
        $a2 = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
        $a3 = "ReflectiveLoader"
        $a4 = "\\Sysnative\\"
        $a5 = "TEMP%u.CMD"
        $a6 = "TEMP%u.PS1"
        $a7 = "\\TEMP%d.%s"
        $a8 = "NtSetContextThread"
        $a9 = "NtResumeThread"
    condition:
        6 of them
}

