rule Windows_Trojan_DragonBreath_b27bc56b {
    meta:
        id = "1tgHRVnAyTPHZZS5IFs01O"
        fingerprint = "v1_sha256_b86d5541a7e03a698ad918cdbba987474c6680353b4d2de2f8422ecd0ebcac61"
        version = "1.0"
        date = "2024-06-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DragonBreath"
        reference_sample = "45023fd0e694d66c284dfe17f78c624fd7e246a6c36860a0d892d232a30949be"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 50 6C 75 67 69 6E 4D 65 }
        $a2 = { 69 73 41 52 44 6C 6C }
        $a3 = { 25 64 2D 25 64 2D 25 64 20 25 64 3A 25 64 }
    condition:
        all of them
}

