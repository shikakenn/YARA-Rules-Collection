rule Linux_Cryptominer_Loudminer_581f57a9 {
    meta:
        id = "44E6rZ9g4IjSSs6T1LrkqB"
        fingerprint = "v1_sha256_82db0985f215da1d84e16fce94df7553b43b06082bf5475515dbbcf016c40fe4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 44 24 08 48 8B 70 20 48 8B 3B 48 83 C3 08 48 89 EA 48 8B 07 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Loudminer_f2298a50 {
    meta:
        id = "5TJAXhlYuWREM3jTpEcgDX"
        fingerprint = "v1_sha256_6c2c9b6aea1fb35f8f600dd084ed9cfd56123f7502036e76dd168ccd8b43b28f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B6 04 07 41 8D 40 D0 3C 09 76 AD 41 8D 40 9F 3C 05 76 A1 41 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Loudminer_851fc7aa {
    meta:
        id = "5wzZNeAwCLjDS7ZBRMzrDG"
        fingerprint = "v1_sha256_9f271a16fe30fbf0c16533522b733228f19e0c44d173e4c0ef43bf13323e7383"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 49 8B 45 00 4C 8B 40 08 49 8D 78 18 49 89 FA 49 29 D2 49 01 C2 4C }
    condition:
        all of them
}

