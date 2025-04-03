rule Windows_Trojan_Afdk_c952fcfa {
    meta:
        id = "5LY1X4ShiQJ2nmBquv2sfc"
        fingerprint = "v1_sha256_a0589a3bf9e733e615b6e552395b3ff513e4fad7efd7d2ebea634aa91d2f60d9"
        version = "1.0"
        date = "2023-12-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Afdk"
        reference_sample = "6723a9489e7cfb5e2d37ff9160d55cda065f06907122d73764849808018eb7a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 51 51 83 65 F8 00 8D 45 F8 83 65 FC 00 50 E8 80 FF FF FF 59 85 C0 75 2B 8B 4D 08 8B 55 F8 8B 45 FC 89 41 04 8D 45 F8 89 11 83 CA 1F 50 89 55 F8 E8 7B FF FF FF 59 85 C0 75 09 E8 DA 98 }
    condition:
        all of them
}

rule Windows_Trojan_Afdk_5f8cc135 {
    meta:
        id = "2AVThS89QZwlRWvrNIIx3K"
        fingerprint = "v1_sha256_0523a0cc3a4446f2ac88c72999568313c6b40f7f8975b8e332c0c6b1e48c5d76"
        version = "1.0"
        date = "2023-12-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Afdk"
        reference_sample = "6723a9489e7cfb5e2d37ff9160d55cda065f06907122d73764849808018eb7a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Cannot set the log file name"
        $a2 = "Cannot install the hook procedure"
        $a3 = "Keylogger is up and running..."
    condition:
        2 of them
}

