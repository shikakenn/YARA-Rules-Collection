rule Windows_Trojan_PikaBot_8c6750b5 {
    meta:
        id = "6U6omqqRjipcbvIkKYXsXR"
        fingerprint = "v1_sha256_03e36f927513625d1dd997c79843b1b14e344e8411155740213d7aff9794c5c6"
        version = "1.0"
        date = "2023-06-05"
        modified = "2023-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
        threat_name = "Windows.Trojan.PikaBot"
        reference_sample = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $byte_seq0 = { B8 00 00 00 00 CD 2D 90 C3 CC CC CC CC CC CC CC }
        $byte_seq1 = { 64 A1 30 00 00 00 8B 40 ?? C3 }
        $byte_seq2 = { 8B 45 FC 8B 44 85 B4 89 45 F0 8B 45 08 89 45 F8 8B 45 10 C1 E8 02 89 45 F4 }
        $byte_seq3 = { 8B 4C 8D BC ?? 75 FC 33 C0 64 A1 30 00 00 00 8B 40 68 83 E0 70 89 45 FC }
        $byte_seq4 = { 8B 45 F8 8B 4D 0C 89 08 8B 45 F8 83 C0 04 89 45 F8 8B 45 F4 48 89 45 F4 }
        $byte_seq5 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 C3 }
    condition:
        4 of them
}

rule Windows_Trojan_PikaBot_5b220e9c {
    meta:
        id = "6G6pV4qvfiz7xqMoxVNPzG"
        fingerprint = "v1_sha256_1d2158716b7c32734f12f8528352a3872e21fea2f9b21a36d6ac44fcd50a9f3c"
        version = "1.0"
        date = "2024-02-06"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
        threat_name = "Windows.Trojan.PikaBot"
        reference_sample = "d836b06b0118e6d258e318b1cfdc509cacc0859c6a6b3d7c5f4d2525e00d97b2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $byte_seq0 = { 03 44 95 ?? 42 83 FA ?? 7C ?? EB ?? }
        $byte_seq1 = { 3B C1 73 ?? 80 3C 18 ?? 75 ?? C6 04 18 ?? 40 EB ?? }
        $byte_seq2 = { 03 C7 03 C8 0F B6 F9 8A 84 3D 34 FD FF FF 88 84 35 34 FD FF FF }
        $byte_seq3 = { 55 8B EC 83 EC 0C 33 C0 C7 45 F4 05 00 00 00 C7 45 F8 32 00 00 00 8B D0 C7 45 FC C9 FF FF FF }
        $byte_seq4 = { 55 8B EC 51 51 53 56 89 55 F8 89 4D FC 8B 75 FC 8B 45 F8 33 C9 0F A2 89 06 89 5E 04 89 4E 08 89 }
        $byte_seq5 = { 8D 5D E8 59 33 D2 C7 45 F8 04 00 00 00 8A 03 8D 0C 16 43 88 04 39 83 6D F8 01 8D 52 04 75 EE 46 }
        $byte_seq6 = { 55 8B EC 51 51 53 56 89 55 F8 89 4D FC 8B 75 FC 8B 45 F8 33 C9 0F A2 89 06 89 5E 04 89 4E 08 89 }
    condition:
        2 of them
}

rule Windows_Trojan_PikaBot_5441f511 {
    meta:
        id = "2Yt7VM4yAoxlzMLJv8fTHq"
        fingerprint = "v1_sha256_fa44408874c6a007212dfc206cbecbac7a3e50df94da4ce02de2e04e9119c79f"
        version = "1.0"
        date = "2024-02-15"
        modified = "2024-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Related to Pikabot core"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
        threat_name = "Windows.Trojan.PikaBot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $handler_table = { 72 26 [6] 6F 24 [6] CB 0A [6] 6C 03 [6] 92 07 }
        $api_hashing = { 3C 60 76 ?? 83 E8 20 8B 0D ?? ?? ?? ?? 6B FF 21 }
        $debug_check = { A1 ?? ?? ?? ?? FF 50 ?? 50 50 80 7E ?? 01 74 ?? 83 7D ?? 00 75 ?? }
        $checksum = { 55 89 E5 8B 55 08 69 02 E1 10 00 00 05 38 15 00 00 89 02 5D C3 }
        $load_sycall = { 8F 05 ?? ?? ?? ?? 83 C0 04 50 8F 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 A3 ?? ?? ?? ?? 31 C0 64 8B 0D C0 00 00 00 85 C9 }
        $read_xbyte_config = { 8B 43 04 8B 55 F4 B9 FC FF FF FF 83 C0 04 29 D1 01 4B 0C 8D 0C 10 89 4B 04 85 F6 ?? ?? 89 16 89 C3 }
    condition:
        2 of them
}

rule Windows_Trojan_PikaBot_95db8b5a {
    meta:
        id = "coEai7NArJyVl3VDElsY6"
        fingerprint = "v1_sha256_74073ceae1b26b953b7644d56a2ec92993b83802a30ce82c6921df5448ebab06"
        version = "1.0"
        date = "2024-02-15"
        modified = "2024-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Related to Pikabot loader"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
        threat_name = "Windows.Trojan.PikaBot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $syscall_ZwQueryInfoProcess = { 68 9B 8B 16 88 E8 73 FF FF FF }
        $syscall_ZwCreateUserProcess = { 68 B2 CE 2E CF E8 5F FF FF FF }
        $load_sycall = { 8F 05 ?? ?? ?? ?? 83 C0 04 50 8F 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 A3 ?? ?? ?? ?? 31 C0 64 8B 0D C0 00 00 00 85 C9 }
        $payload_chunking = { 8A 84 35 ?? ?? ?? ?? 8A 95 ?? ?? ?? ?? 88 84 1D ?? ?? ?? ?? 88 94 35 ?? ?? ?? ?? 02 94 1D ?? ?? ?? ?? }
        $loader_rc4_decrypt_chunk = { F7 FF 8A 84 15 ?? ?? ?? ?? 89 D1 8A 94 1D ?? ?? ?? ?? 88 94 0D ?? ?? ?? ?? 8B 55 08 88 84 1D ?? ?? ?? ?? 02 84 0D ?? ?? ?? ?? 0F B6 C0 8A 84 05 ?? ?? ?? ?? 32 04 32 }
    condition:
        2 of them
}

