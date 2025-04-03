rule Linux_Cryptominer_Uwamson_c42fd06d {
    meta:
        id = "2TC1iLovv6BC0BmA6WiLfy"
        fingerprint = "v1_sha256_4ff7aad11adaae8fccb23d36fc96937ba48a5517895a742f2864ba1973f3db3a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F0 4C 89 F3 48 8B 34 24 48 C1 E0 04 48 C1 E3 07 48 8B 7C 24 10 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_d08b1d2e {
    meta:
        id = "7M9XW8Hnya8b7yloLSmgpT"
        fingerprint = "v1_sha256_8f489bb020397beae91f7bce82bc1b47912deab1b79224158f79c53f1d7c7fd3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "4f7ad24b53b8e255710e4080d55f797564aa8c270bf100129bdbe52a29906b78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4F F8 49 8D 7D 18 89 D9 49 83 C5 20 48 89 FE 41 83 E1 0F 4D 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_0797de34 {
    meta:
        id = "6V3wb7qhHa7xEJOjJkxO4P"
        fingerprint = "v1_sha256_7ab5dd99d8bbef61ec764900df5bebf39ed90833a8f9481c427cbb46faf2c521"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "e4699e35ce8091f97decbeebff63d7fa8c868172a79f9d9d52b6778c3faab8f2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 43 20 48 B9 AB AA AA AA AA AA AA AA 88 44 24 30 8B 43 24 89 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_41e36585 {
    meta:
        id = "3RmzWJKIO1iqSeB4MVcBZV"
        fingerprint = "v1_sha256_e176523afe8c3394ddda41a5ef11f825fed1e149476709a7c1ea26b8af72d4fc"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 03 48 C1 FF 03 4F 8D 44 40 FD 48 0F AF FE 49 01 F8 4C 01 C2 4C }
    condition:
        all of them
}

