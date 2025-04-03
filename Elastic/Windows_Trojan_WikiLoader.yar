rule Windows_Trojan_WikiLoader_c57f3f88 {
    meta:
        id = "2J9J5U32EPuHMBzD87km7K"
        fingerprint = "v1_sha256_408c6d811232dbd0c87f75fd28508366151cf9f2f10f012919588db1919e406b"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.WikiLoader"
        reference_sample = "0f71b1805d7feb6830b856c5a5328d3a132af4c37fcd747d82beb0f61c77f6f5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 81 EC 08 01 00 00 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 89 E7 F3 AA 48 89 D9 48 89 4D 80 48 89 95 78 FF FF FF 4C 89 45 C0 4C 89 4D 88 4D 89 D4 4D 89 DD 4C 89 65 C8 49 83 ED 10 4C 89 6D 98 }
    condition:
        all of them
}

rule Windows_Trojan_WikiLoader_99681f1c {
    meta:
        id = "62rTw7Sq1Lm8t7LozTAnfM"
        fingerprint = "v1_sha256_fb293d74186e778856780377120ac2ebe9550a508a0b33e706c39f93a5509df8"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.WikiLoader"
        reference_sample = "0b02cfe16ac73f2e7dc52eaf3b93279b7d02b3d64d061782dfed0c55ab621a8e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 83 EC 08 48 89 E0 4C 89 20 48 83 EC 08 48 89 E0 4C 89 28 48 83 EC 08 48 89 E0 4C 89 30 48 83 EC 08 48 89 E0 4C 89 38 48 89 E5 48 83 EC 08 48 83 EC 60 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 }
    condition:
        all of them
}

