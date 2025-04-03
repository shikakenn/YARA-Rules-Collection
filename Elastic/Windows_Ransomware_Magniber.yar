rule Windows_Ransomware_Magniber_ea0140a1 {
    meta:
        id = "2ijFyyG0YvmcFKOR838P0v"
        fingerprint = "v1_sha256_e2c05e2c92444d7bcb2bf68e97f809072d2ccdc8a171214d2e7a498b20d08f90"
        version = "1.0"
        date = "2021-08-03"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Magniber"
        reference_sample = "a2448b93d7c50801056052fb429d04bcf94a478a0a012191d60e595fed63eec4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 58 C0 FF 24 4C 8B F0 48 89 45 18 E8 E2 F5 FF FF B9 A1 BD D1 CF 48 89 45 B8 E8 D4 F5 FF FF B9 52 C6 D7 0E 48 89 45 F8 E8 C6 F5 FF FF B9 43 AC 95 0E 48 89 45 B0 E8 B8 F5 FF FF B9 78 D4 33 27 4C 8B F8 48 89 45 D0 E8 A7 F5 FF FF B9 FE 36 04 DE 48 89 44 24 50 E8 98 F5 FF FF B9 51 23 2E F2 48 89 45 10 E8 8A F5 FF FF B9 DA F6 8A 50 48 89 45 08 E8 7C F5 FF FF B9 AD 9E 5F BB 48 89 45 20 E8 6E F5 FF FF B9 2D 57 AE 5B 48 89 45 A0 E8 60 F5 FF FF B9 C6 96 87 52 48 89 45 C8 E8 52 F5 FF FF B9 F6 76 0F 52 48 89 45 A8 E8 44 F5 FF FF B9 A3 FC 62 AA 48 8B F0 48 89 45 98 E8 33 F5 }
    condition:
        any of them
}

rule Windows_Ransomware_Magniber_97d7575b {
    meta:
        id = "4tj9Qyh5l8ouFzWErPPPkL"
        fingerprint = "v1_sha256_9c85f98aaae28e9e90a94d6ce18389467013ea6b569f46f6acaf26a6c7e027fc"
        version = "1.0"
        date = "2021-08-03"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Magniber"
        reference_sample = "a2448b93d7c50801056052fb429d04bcf94a478a0a012191d60e595fed63eec4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 00 4C 00 4C 00 20 00 59 00 4F 00 55 00 52 00 20 00 44 00 4F 00 43 00 55 00 4D 00 45 00 4E 00 54 00 53 00 20 00 50 00 48 00 4F 00 54 00 4F 00 53 00 20 00 44 00 41 00 54 00 41 00 42 00 41 00 53 00 45 00 53 00 20 00 41 00 4E 00 44 00 20 00 4F 00 54 00 48 00 45 00 52 00 20 00 49 00 4D 00 50 00 4F 00 52 00 54 00 41 00 4E 00 54 00 20 00 46 00 49 00 4C 00 45 00 53 00 20 00 48 00 41 00 56 00 45 00 20 00 42 00 45 00 45 00 4E 00 20 00 45 00 4E 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 21 00 0D }
    condition:
        any of them
}

