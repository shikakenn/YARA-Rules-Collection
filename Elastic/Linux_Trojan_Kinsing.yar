rule Linux_Trojan_Kinsing_196523fa {
    meta:
        id = "6Wrj6qar4faFAXAqikleoW"
        fingerprint = "v1_sha256_baa5808fcf22700ae96844dbf8cb3bec52425eec365d2ba4c71b73ece11a69a2"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kinsing"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 64 65 38 5F 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 35 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_7cdbe9fa {
    meta:
        id = "2cfKDpxxhtZpDCgszLS3E8"
        fingerprint = "v1_sha256_c6f5d2cf0430301ec0eae57808100203b69428f258e0e6882fecbc762d73f4bf"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 73 2E 72 75 22 20 7C 20 61 77 6B 20 27 7B 70 72 69 6E 74 20 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_2c1ffe78 {
    meta:
        id = "2WTjvaYk2QsJLmyI3GYW35"
        fingerprint = "v1_sha256_9561511710eef5877c5afa49890b77fbad31a6e312b5cd33fc01f91ff2a73583"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 73 74 73 20 22 24 42 49 4E 5F 46 55 4C 4C 5F 50 41 54 48 22 20 22 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_85276fb4 {
    meta:
        id = "1gaInIZk6kGqO9p2puOwXV"
        fingerprint = "v1_sha256_6919afd133e7e369eece10ea79d9d17a1a3fbb6210593395e0be157f8c262811"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 65 5F 76 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 38 48 83 }
    condition:
        all of them
}

