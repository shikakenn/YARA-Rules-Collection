rule MacOS_Trojan_Adload_4995469f {
    meta:
        id = "3SykQ9cOOgxqcXWRURCn2d"
        fingerprint = "v1_sha256_cceb804a11b93b0e3f491016c47a823d9e6a31294c3ed05d4404601323b30993"
        version = "1.0"
        date = "2021-10-04"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "6464ca7b36197cccf0dac00f21c43f0cb09f900006b1934e2b3667b367114de5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 49 8B 77 08 49 8B 4F 20 48 BF 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E7 48 C1 }
    condition:
        all of them
}

rule MacOS_Trojan_Adload_9b9f86c7 {
    meta:
        id = "7KVfK5MJmD1clS5c1jThbR"
        fingerprint = "v1_sha256_82297db23e036f22c90eee7b2654e84df847eb1c2b1ea4dcf358c48a14819709"
        version = "1.0"
        date = "2021-10-04"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "952e6004ce164ba607ac7fddc1df3d0d6cac07d271d90be02d790c52e49cb73c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 44 65 6C 65 67 61 74 65 43 35 73 68 6F 77 6E 53 62 76 70 57 76 64 }
    condition:
        all of them
}

rule MacOS_Trojan_Adload_f6b18a0a {
    meta:
        id = "2IjFetdWlRn46LtGXOed5R"
        fingerprint = "v1_sha256_20d43fbf0b8155940e2e181f376a7b1979ce248d88dc08409aaa1a916777231c"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "06f38bb811e6a6c38b5e2db708d4063f4aea27fcd193d57c60594f25a86488c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 10 49 8B 4E 20 48 BE 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E6 49 39 DC 0F 84 }
    condition:
        all of them
}

