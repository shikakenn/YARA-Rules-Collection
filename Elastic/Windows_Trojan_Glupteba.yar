rule Windows_Trojan_Glupteba_70557305 {
    meta:
        id = "aD7CflBPwZkBLPZ6a1Vme"
        fingerprint = "v1_sha256_f3eee9808a1e8a2080116dda7ce795815e1179143c756ea8fdd26070f1f8f74a"
        version = "1.0"
        date = "2021-08-08"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Glupteba"
        reference_sample = "3ad13fd7968f9574d2c822e579291c77a0c525991cfb785cbe6cdd500b737218"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%TEMP%\\app.exe && %TEMP%\\app.exe"
        $a2 = "is unavailable%d smbtest"
        $a3 = "discovered new server %s"
        $a4 = "uldn't get usernamecouldn't hide servicecouldn't"
        $a5 = "TERMINATE PROCESS: %ws, %d, %d" ascii fullword
        $a6 = "[+] Extracting vulnerable driver as \"%ws\"" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Glupteba_4669dcd6 {
    meta:
        id = "6me70uAwkiErF2HIXI9unn"
        fingerprint = "v1_sha256_64b2099f40f94b17bc5860b41773c41322420500696d320399ff1c016cb56e15"
        version = "1.0"
        date = "2021-08-08"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Glupteba"
        reference_sample = "1b55042e06f218546db5ddc52d140be4303153d592dcfc1ce90e6077c05e77f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 40 C3 8B 44 24 48 8B 4C 24 44 89 81 AC 00 00 00 8B 44 24 4C 89 81 B0 00 }
    condition:
        all of them
}

