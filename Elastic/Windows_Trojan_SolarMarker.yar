rule Windows_Trojan_SolarMarker_d466e548 {
    meta:
        id = "5TCzHCea25h05MT6ctFYby"
        fingerprint = "v1_sha256_c0792bc3c1a2f01ff4b8d0a12c95a74491c2805c876f95a26bbeaabecdff70e9"
        version = "1.0"
        date = "2023-12-12"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SolarMarker"
        reference_sample = "330f5067c93041821be4e7097cf32fb569e2e1d00e952156c9aafcddb847b873"
        reference_sample = "e2a620e76352fa7ac58407a711821da52093d97d12293ae93d813163c58eb84b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 00 00 2B 03 00 2B 15 00 07 2D 09 08 16 FE 01 16 FE 01 2B 01 17 00 13 04 11 04 2D 8C 07 2D 06 08 }
    condition:
        all of them
}

rule Windows_Trojan_SolarMarker_08bfc26b {
    meta:
        id = "5CjqCMb2gA8yzWx6dXtk4T"
        fingerprint = "v1_sha256_b31b9f8460b606426c1101eba39a41a75c7ecaafc62388a6a5ac0f24057561ed"
        version = "1.0"
        date = "2024-05-29"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SolarMarker"
        reference_sample = "c1a6d2d78cc50f080f1fe4cadc6043027bf201d194f2b73625ce3664433a3966"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 07 09 91 61 D2 9C 09 20 C8 00 00 00 5D 16 FE 01 16 FE 01 13 }
        $a2 = { 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE 01 16 FE 01 }
        $a3 = { 06 08 06 08 91 07 08 91 61 D2 9C 08 20 C8 00 00 00 5D 16 FE }
    condition:
        any of them
}

