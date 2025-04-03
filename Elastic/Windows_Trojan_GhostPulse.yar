rule Windows_Trojan_GhostPulse_a1311f49 {
    meta:
        id = "3LDz01fjNxcAOn4X0JzhaO"
        fingerprint = "v1_sha256_21838f230ac1a77f09d01d30f4ea3b66313618660e63ab7012b030e0b819547e"
        version = "1.0"
        date = "2023-10-06"
        modified = "2023-10-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "0175448655e593aa299278d5f11b81f2af76638859e104975bdb5d30af5c0c11"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 0F BE 00 48 0F BE C0 85 C0 74 0D B8 01 00 00 00 03 45 00 89 45 00 EB E1 8B 45 00 48 8D 65 10 5D C3 }
        $a2 = { 88 4C 24 08 48 83 EC 18 0F B6 44 24 20 88 04 24 0F BE 44 24 20 83 F8 41 7C 13 0F BE 04 24 83 F8 5A 7F 0A 0F BE 04 24 83 C0 20 88 04 24 }
    condition:
        any of them
}

rule Windows_Trojan_GhostPulse_3fe1d02d {
    meta:
        id = "VWOfqBULfrZBltQuJ5yLw"
        fingerprint = "v1_sha256_4ef78d436a153ed751a8483c1e43ec2ba053dedfa0da2780fded42012d3042c1"
        version = "1.0"
        date = "2023-10-12"
        modified = "2023-10-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
        threat_name = "Windows.Trojan.GhostPulse"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 89 5C 24 08 48 89 7C 24 10 8B DA 45 33 D2 48 8B F9 41 2B D9 74 50 4C 8B D9 4C 2B C1 0F 1F 00 33 C9 }
    condition:
        all of them
}

rule Windows_Trojan_GhostPulse_3673d337 {
    meta:
        id = "447HqgII2USnzqShzGM5ez"
        fingerprint = "v1_sha256_a92815f27533338e17afd5ebdbe82e382636fb81167a82d1b613c0dccc5b7ed3"
        version = "1.0"
        date = "2023-12-11"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "3013ba32838f6d97d7d75e25394f9611b1c5def94d93588f0a05c90b25b7d6d5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $IDAT_parser_x86 = { 80 F9 3F 75 ?? 38 54 1E 02 74 ?? 80 FA 3F 75 ?? 38 6C 1E 03 74 ?? 80 FD 3F 75 ?? 8A 74 24 04 38 74 1E 04 }
        $IDAT_parser_x64 = { 80 FB 3F 0F 94 44 24 27 3C 3F 0F 94 44 24 30 40 80 FF 3F 0F 94 44 24 31 41 80 FD 3F 0F 94 44 24 32 41 80 FC 3F 0F 94 44 24 33 }
    condition:
        any of them
}

rule Windows_Trojan_GhostPulse_8ae8310b {
    meta:
        id = "1V6dS1hwUY6COXSWd8VALM"
        fingerprint = "v1_sha256_b3873a3c728e98d65984033620c0ac8ee93be21db5b6d9bd4665b9f7d0d759fa"
        version = "1.0"
        date = "2024-05-27"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "5b64f91b41a7390d89cd3b1fccf02b08b18b7fed17a43b0bfac63d75dc0df083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 8B 84 24 ?? 0D 00 00 8B 40 14 0F BA E8 09 48 8B 8C 24 ?? 0D 00 00 89 41 14 48 8B 84 24 ?? 0D 00 00 48 8B 8C 24 ?? 05 00 00 48 89 88 C0 ?? 00 00 }
        $b = { BA C8 90 F0 B2 48 8B ?? ?? ?? E8 ?? ?? ?? 00 48 89 ?? ?? ?? 07 00 00 BA 9C 6C DA DC 48 8B ?? ?? ?? E8 ?? ?? ?? 00 48 89 ?? ?? ?? 07 00 00 BA 8D 20 4A A1 48 8B ?? ?? ?? E8 ?? ?? ?? 00 48 89 ?? ?? ?? 07 00 00 BA D4 7C 1A A8 }
    condition:
        any of them
}

rule Windows_Trojan_GhostPulse_9e22c56d {
    meta:
        id = "1cKUy5gbh0LaiWzkqrvT02"
        fingerprint = "v1_sha256_5dbd0d6a936a73e933181017c67c36fde7576b47643ec00848f7b58170bd9c6b"
        version = "1.0"
        date = "2024-07-21"
        modified = "2024-07-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "349b4dfa1e93144b010affba926663264288a5cfcb7b305320f466b2551b93df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { C7 44 24 28 80 3C 36 FE C7 44 24 2C FF FF FF FF 53 6A 00 }
        $b = { 80 7C 24 04 3F ?? ?? 8A 74 24 08 38 74 1E 05 8A 6C 24 10 ?? ?? 80 7C 24 08 3F }
        $c = { 89 41 5C 8B 44 24 ?? 8B 80 04 01 00 00 89 44 24 ?? 8B 42 3C 8B 44 02 78 8B 4C 02 20 01 D1 89 4C 24 ?? 8B 4C 02 1C 89 4C 24 ?? 8B 44 02 24 89 44 }
    condition:
        any of them
}

rule Windows_Trojan_GhostPulse_bb38fcb3 {
    meta:
        id = "59xxHq85ciE74HLgXzrA6j"
        fingerprint = "v1_sha256_95a7f663f0bac81a5426d722ec95e11f37fcde45cbf8ebd4e32b9f4c72873c2b"
        version = "1.0"
        date = "2024-10-15"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "b54d9db283e6c958697bfc4f97a5dd0ba585bc1d05267569264a2d700f0799ae"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $stage_1 = { 49 63 D0 42 8B 0C 0A 41 03 CA 89 0C 1A 8B 05 ?? ?? ?? ?? 44 03 C0 8B 05 ?? ?? ?? ?? 44 3B C0 }
        $stage_2 = { 48 89 01 48 8B 84 24 D8 00 00 00 48 8B 4C 24 78 8B 49 0C 89 08 C7 44 24 44 00 00 00 00 }
    condition:
        any of them
}

rule Windows_Trojan_GhostPulse_caea316b {
    meta:
        id = "1UxKZQC32NPTbh50BkUdap"
        fingerprint = "v1_sha256_740dad0ce9d6b7c5a4125db9c6ad36e767bacba478ee627032b7fe00431c6d7b"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.GhostPulse"
        reference_sample = "454e898405a10ecc06b4243c25f86c855203722a4970dee4c4e1a4e8e75f5137"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 83 EC 18 C7 04 24 00 00 00 00 8B 04 24 48 8B 4C 24 20 0F B7 04 41 85 C0 74 0A 8B 04 24 FF C0 89 04 24 EB E6 C7 44 24 08 00 00 00 00 8B 04 24 FF C8 8B C0 48 8B 4C 24 20 0F B7 04 41 83 F8 5C }
    condition:
        all of them
}

