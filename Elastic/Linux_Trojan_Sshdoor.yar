rule Linux_Trojan_Sshdoor_5b78aa01 {
    meta:
        id = "57WekrSbwPhpix571Hk5Fd"
        fingerprint = "v1_sha256_bcf285ac220b2b2ed9caf0943fa22ee830e5b26501c54a223e483a33e2fc63c0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "2e1d909e4a6ba843194f9912826728bd2639b0f34ee512e0c3c9e5ce4d27828e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 11 75 39 41 0F B6 77 01 4C 89 E2 40 84 F6 74 2C 40 80 FE 5A }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_1b443a9b {
    meta:
        id = "2ZGGq6w9aEeiPSgMzwy3Dm"
        fingerprint = "v1_sha256_4afcd7103a14d59abc08d9e03182a985e3d0250c09aad5e81fd110c6a95f29e0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "a33112daa5a7d31ea1a1ca9b910475843b7d8c84d4658ccc00bafee044382709"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 10 44 39 F8 7F B4 3B 44 24 04 7C AE 3B 44 24 0C 7E 10 41 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_7c36d3dd {
    meta:
        id = "MuzUqv61CSPYN9UcYITld"
        fingerprint = "v1_sha256_c1b61fce7593a44e47043fac8a6356f9aa9e74b66db005400684a5a79b69a5cd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 20 48 89 E7 C1 EE 03 83 E6 01 FF D3 8B 54 24 20 31 C0 BE 20 00 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_3e81b1b7 {
    meta:
        id = "7j8IMXjEInLgWA3rFhvbqf"
        fingerprint = "v1_sha256_54253df560e6552a728dc2651c557bc23ae8ec4847760290701438821c52342e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 24 48 89 E7 C1 EE 05 83 E6 01 FF D3 8B 54 24 28 31 C0 BE 5A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_cde7cfd4 {
    meta:
        id = "6HQNRR0OEgndwtfeeTJhYE"
        fingerprint = "v1_sha256_47967d90a6dbb4461e22998aff5b7e68b4b9007ea7e5e30574ae1f1cfcbaa573"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "cd646a1d59c99b9e038098b91cdb63c3fe9b35bb10583bef0ab07260dbd4d23d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 75 CC 8B 73 08 48 8B 54 24 08 48 83 C4 18 5B 5D 41 5C 41 5D 4C }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_32d9fb1b {
    meta:
        id = "5ap70U9tDCYZZzYoFqCL4p"
        fingerprint = "v1_sha256_35ef4f3970484a46d705e6976a9932639d576717454b8e07ed24a72114d9c42d"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 04 25 28 00 00 00 48 89 44 24 08 31 C0 66 0F EF C0 48 85 F6 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_7c3cfc62 {
    meta:
        id = "27wvhj1Vo9dCqoslnQxu1e"
        fingerprint = "v1_sha256_da9804489f30b575d2b459f82570f5df07c1777f105cd373c4268f8a31fa4e43"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 48 8D 6F 50 53 49 89 FC 48 89 FB 48 83 EC 10 64 48 8B 04 25 28 00 }
    condition:
        all of them
}

