rule Linux_Trojan_Mobidash_52a15a93 {
    meta:
        id = "2MEtPituTqSbwwlUBU5jSo"
        fingerprint = "v1_sha256_ceaf5b06108baa6043e31010d777099ed6ac9b4054e86d41309bd7c2b0ffda11"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 89 CE 41 55 41 54 49 89 F4 55 48 89 D5 53 48 89 FB 48 8B 07 FF 90 F8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_d0ad9c82 {
    meta:
        id = "5JIvW9QBxhIr87XqlVMZyx"
        fingerprint = "v1_sha256_8351cb61f5b712c65962e734a7c29271fa4805720e14b6badc9bc1c0364778f8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 48 8D 64 24 F8 48 8B 07 FF 90 F8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_e2c89606 {
    meta:
        id = "3YxHYKs39FpwuK76xN8VhM"
        fingerprint = "v1_sha256_64cb8d8ec04a53f663b216208279afba3c10f148fe99822f9a45100a4f73ed28"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 13 49 89 C7 4C 89 E6 48 89 DF FF 92 B8 00 00 00 31 C9 4C 89 FA 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_82b4e3f3 {
    meta:
        id = "4MwqubsAbSFhysRVF9O7l7"
        fingerprint = "v1_sha256_8c91f85bc807605a3233d28a5eb8b6e1cf847fb288cbc4427e86226eed7a2055"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C6 74 2E 89 44 24 0C 8B 44 24 24 C7 44 24 08 01 00 00 00 89 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_601352dc {
    meta:
        id = "2xRLA4cger7EVoo2Cp4J9q"
        fingerprint = "v1_sha256_adeeea73b711fc867b88775c06a14011380118ed85691660ba771381e51160e3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "5714e130075f4780e025fb3810f58a63e618659ac34d12abe211a1b6f2f80269"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F6 74 14 48 8B BC 24 D0 00 00 00 48 8B 07 48 8B 80 B8 00 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_ddca1181 {
    meta:
        id = "41E3PjfablQDT530FQRhzF"
        fingerprint = "v1_sha256_076d4ac69f6bc29975b22e19d429c25ef357443ec8fcaf5165e0a8069112af74"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 84 C0 75 1E 8B 44 24 2C 89 7C 24 04 89 34 24 89 44 24 0C 8B 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_65e666c0 {
    meta:
        id = "6LUBLudxvfAejMLihTGGK1"
        fingerprint = "v1_sha256_2d2bec8f89986b19bf1c806b6654405ac6523f49aeafd759b7631d9587d780c8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "19f9b5382d3e8e604be321aefd47cb72c2337a170403613b853307c266d065dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4C 8B 44 24 08 48 89 DF 48 8B 14 24 48 8D 64 24 18 5B 4C 89 E6 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_494d5b0f {
    meta:
        id = "3BItJqJMLXZwAG17fOXsFg"
        fingerprint = "v1_sha256_6ddb94f9f44fe749a442592d491343a99bd870ea2d79596631d857516425e72b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "7e08df5279f4d22f1f27553946b0dadd60bb8242d522a8dceb45ab7636433c2f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 18 00 00 00 40 04 00 00 01 5B 00 00 00 3A 00 00 00 54 04 00 00 05 A1 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_bb4f7f39 {
    meta:
        id = "2tw5Bc3hajUV9fCKaXb2hD"
        fingerprint = "v1_sha256_33e8fcbb29cc38b4a8365845eb3a1488e13be964f7383b28a158a98fb259acb4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 75 1F 48 8D 64 24 08 48 89 DF 5B 48 89 EA 4C 89 E1 4C 89 EE 5D }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_8679e1cb {
    meta:
        id = "3Gts6Hr4DMrk2FB6JRwf9B"
        fingerprint = "v1_sha256_6055ac4800397f6582e60cdf15fa74584986e1e7cf49a541b0ec746445834819"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 1C 89 F0 5B 5E 5F 5D C3 8D 76 00 8B 44 24 34 83 C6 01 8D 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_29b86e6a {
    meta:
        id = "36jN4EhSyxwnez57DUVzs3"
        fingerprint = "v1_sha256_dd5f44249cc4c91f39a0e7d0b236ebeed8f78d5fcb03c7ebc80ef1c738b18336"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 2E 10 73 2E 10 02 47 2E 10 56 2E 10 5C 2E 10 4E 2E 10 49 2E 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_e3086563 {
    meta:
        id = "4MsrEkydIZODiJnDmg3xI2"
        fingerprint = "v1_sha256_5545f7ce8fa45dc56bc4bb5140ce1db527997dfaa1dd2bbb1e4a12af45300065"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 48 8B 4C 24 08 49 8B 55 00 48 39 D1 75 16 48 8D 64 24 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_2f114992 {
    meta:
        id = "6d8jTBIEFmjo8atCxG4T90"
        fingerprint = "v1_sha256_f93fe72e08c8ec135cccc8cdab2ecedbb694e9ad39f2572d060864bb3290e25c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { DF 4C 89 F6 48 8B 80 B8 00 00 00 48 8D 64 24 58 5B 5D 41 5C }
    condition:
        all of them
}

