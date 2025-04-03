rule Windows_Trojan_Qbot_d91c1384 {
    meta:
        id = "2BBALJ7l8NHSj5wO18Sh8D"
        fingerprint = "v1_sha256_8fd8249a2af236c92ccbc20b2a8380f69ca75976bd64bad167828e9ab4c6ed90"
        version = "1.0"
        date = "2021-07-08"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "18ac3870aaa9aaaf6f4a5c0118daa4b43ad93d71c38bf42cb600db3d786c6dda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { FE 8A 14 06 88 50 FF 8A 54 BC 11 88 10 8A 54 BC 10 88 50 01 47 83 }
    condition:
        all of them
}

rule Windows_Trojan_Qbot_7d5dc64a {
    meta:
        id = "5gZZB6qOpzwLmgBIyyiPxX"
        fingerprint = "v1_sha256_5c8858502050494ab20a230f04c2c1cb4bfcd80f4a248dad82787d7ce67c741d"
        version = "1.0"
        date = "2021-10-04"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "a2bacde7210d88675564106406d9c2f3b738e2b1993737cb8bf621b78a9ebf56"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%u.%u.%u.%u.%u.%u.%04x" ascii fullword
        $a2 = "stager_1.dll" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Qbot_6fd34691 {
    meta:
        id = "svZRIE88fMHB8CKRST9Nq"
        fingerprint = "v1_sha256_9422d9f276f0c8c2990ece3282d918abc6fcce7eeb6809d46ae6b768a501a877"
        version = "1.0"
        date = "2022-03-07"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "0838cd11d6f504203ea98f78cac8f066eb2096a2af16d27fb9903484e7e6a689"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 75 C9 8B 45 1C 89 45 A4 8B 45 18 89 45 A8 8B 45 14 89 45 AC 8B }
        $a2 = "\\stager_1.obf\\Benign\\mfc\\" wide
    condition:
        any of them
}

rule Windows_Trojan_Qbot_3074a8d4 {
    meta:
        id = "6mjSEqmseukqT6SWvIIsI0"
        fingerprint = "v1_sha256_90c06bd09fe640bb5a6be8e4f2384fb15c7501674d57db005e790ed336740c99"
        version = "1.0"
        date = "2022-06-07"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "qbot" wide
        $a2 = "stager_1.obf\\Benign\\mfc" wide
        $a3 = "common.obf\\Benign\\mfc" wide
        $a4 = "%u;%u;%u;"
        $a5 = "%u.%u.%u.%u.%u.%u.%04x"
        $a6 = "%u&%s&%u"
        $get_string1 = { 33 D2 8B ?? 6A 5A 5? F7 ?? 8B ?? 08 8A 04 ?? 8B 55 ?? 8B ?? 10 3A 04 ?? }
        $get_string2 = { 33 D2 8B ?? F7 75 F4 8B 45 08 8A 04 02 32 04 ?? 88 04 ?? ?? 83 ?? 01 }
        $set_key = { 8D 87 00 04 00 00 50 56 E8 ?? ?? ?? ?? 59 8B D0 8B CE E8 }
        $do_computer_use_russian_like_keyboard = { B9 FF 03 00 00 66 23 C1 33 C9 0F B7 F8 66 3B 7C 4D }
        $execute_each_tasks = { 8B 44 0E ?? 85 C0 74 ?? FF D0 EB ?? 6A 00 6A 00 6A 00 FF 74 0E ?? E8 ?? ?? ?? ?? 83 C4 10 }
        $generate_random_alpha_num_string = { 57 E8 ?? ?? ?? ?? 48 50 8D 85 ?? ?? ?? ?? 6A 00 50 E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 10 8A 04 38 88 04 0E 46 83 FE 0C }
        $load_base64_dll_from_file_and_inject_into_targets = { 10 C7 45 F0 50 00 00 00 83 65 E8 00 83 7D F0 0B 73 08 8B 45 F0 89 }
    condition:
        6 of them
}

rule Windows_Trojan_Qbot_1ac22a26 {
    meta:
        id = "4UDhoNOkbiTpKwRnWtDoP8"
        fingerprint = "v1_sha256_d9beaf4a8c28a0b3c38dda6bf22a96b8c96ef715bd36de880504a9f970338fe2"
        version = "1.0"
        date = "2022-12-29"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "qbot" wide
        $a2 = "stager_1.obf\\Benign\\mfc" wide
        $a3 = "common.obf\\Benign\\mfc" wide
        $a4 = "%u;%u;%u"
        $a5 = "%u.%u.%u.%u.%u.%u.%04x"
        $a6 = "%u&%s&%u"
        $a7 = "mnjhuiv40"
        $a8 = "\\u%04X"
        $get_string1 = { 33 D2 8B ?? 6A ?? 5? F7 ?? 8B ?? 08 8A 04 ?? 8B 55 ?? 8B ?? 10 3A 04 }
        $get_string2 = { 8B C6 83 E0 ?? 8A 04 08 3A 04 1E 74 ?? 46 3B F2 72 }
        $get_string3 = { 8A 04 ?? 32 04 ?? 88 04 ?? 4? 83 ?? 01 }
        $set_key_1 = { 8D 87 00 04 00 00 50 56 E8 [4] 59 8B D0 8B CE E8 }
        $set_key_2 = { 59 6A 14 58 6A 0B 66 89 87 [0-1] 20 04 00 00 }
        $cccp_keyboard_0 = { 6A ?? 66 89 45 E? 58 6A ?? 66 89 45 E? 58 }
        $cccp_keyboard_1 = { 66 8B 84 9? ?? FE FF FF B9 FF 03 00 00 66 23 C1 33 ?? 0F B7 }
        $execute_each_tasks = { 8B 0D [4] 83 7C 0E 04 00 74 ?? 83 7C 0E 1C 00 74 ?? 8B 04 0E 85 C0 7E ?? 6B C0 3C }
        $generate_random_alpha_num_string = { 57 E8 [4] 48 50 8D 85 [4] 6A 00 50 E8 [4] 8B 4D ?? 83 C4 10 8A 04 38 88 04 0E 46 83 FE 0C }
        $load_and_inject_b64_dll_from_file = { 6B 45 FC 18 8B 4D F8 83 7C 01 04 00 76 ?? 6A 00 6B 45 FC 18 8B 4D F8 FF 74 01 10 6B 45 FC 18 }
        $decipher_rsrc_data = { F6 86 38 04 00 00 04 89 BE 2C 04 00 00 89 BE 28 04 00 00 [2-6] 8B 0B 8D 45 F? 83 65 F? 00 8B D7 50 E8 }
    condition:
        6 of them
}

