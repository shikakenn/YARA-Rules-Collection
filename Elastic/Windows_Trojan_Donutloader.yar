rule Windows_Trojan_Donutloader_f40e3759 {
    meta:
        id = "6kGxUzAFuMvoqSuQ8wKoWl"
        fingerprint = "v1_sha256_541a4ca1da41f7cf54dff3fee917b219fadb60fd93a89b93b5efa3c1a57af81d"
        version = "1.0"
        date = "2021-09-15"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Donutloader"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $x64 = { 06 B8 03 40 00 80 C3 4C 8B 49 10 49 8B 81 30 08 00 00 }
        $x86 = { 04 75 EE 89 31 F0 FF 46 04 33 C0 EB 08 83 21 00 B8 02 }
    condition:
        any of them
}

rule Windows_Trojan_Donutloader_5c38878d {
    meta:
        id = "6BDth5z3ClVScwOMhWhu3p"
        fingerprint = "v1_sha256_897880d13318027ac5008fe8d008f09780d6fa807d6cc828b57975443358750c"
        version = "1.0"
        date = "2021-09-15"
        modified = "2021-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Donutloader"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 24 48 03 C2 48 89 44 24 28 41 8A 00 84 C0 74 14 33 D2 FF C1 }
    condition:
        any of them
}

rule Windows_Trojan_Donutloader_21e801e0 {
    meta:
        id = "4pBkmOTLKJro1e3SngjOyx"
        fingerprint = "v1_sha256_19ef7bc8c7117024ca72956376954254c36eeb673f9379aa00475f763084a169"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Donutloader"
        reference_sample = "c3bda62725bb1047d203575bbe033f0f95d4dd6402c05f9d0c69d24bd3224ca6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 89 45 F0 48 8B 45 F0 48 81 C4 D0 00 00 00 5D C3 55 48 81 EC 60 02 00 00 48 8D AC 24 80 00 00 00 48 89 8D F0 01 00 00 48 89 95 F8 01 00 00 4C 89 85 00 02 00 00 4C 89 8D 08 02 00 00 48 C7 85 }
    condition:
        all of them
}

