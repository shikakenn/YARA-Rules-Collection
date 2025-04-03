rule Windows_Trojan_Smokeloader_4e31426e {
    meta:
        id = "4WaserEo6DDeD5ajlev83f"
        fingerprint = "v1_sha256_44ac7659964519ae72f83076bcd1b3e5244eb9cadd9a3b123dda78b0e9e07424"
        version = "1.0"
        date = "2021-07-21"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "1ce643981821b185b8ad73b798ab5c71c6c40e1f547b8e5b19afdaa4ca2a5174"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 5B 81 EB 34 10 00 00 6A 30 58 64 8B 00 8B 40 0C 8B 40 1C 8B 40 08 89 85 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_4ee15b92 {
    meta:
        id = "32XTFhkCEaZYEVCXuLIgz5"
        fingerprint = "v1_sha256_7d5ba6a4cc1f1b87f7ea1963b41749f5488197ea28b31f20a235091236250463"
        version = "1.0"
        date = "2022-02-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "09b9283286463b35ea2d5abfa869110eb124eb8c1788eb2630480d058e82abf2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 24 34 30 33 33 8B 45 F4 5F 5E 5B C9 C2 10 00 55 89 E5 83 EC }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_ea14b2a5 {
    meta:
        id = "7We6NW06sWGvIXYA0z4sSn"
        fingerprint = "v1_sha256_8a96985902f82979f1512d4d30cfa41fd23562b8f86bf2f722351ef2adf4365f"
        version = "1.0"
        date = "2023-05-03"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "15fe237276b9c2c6ceae405c0739479d165b406321891c8a31883023e7b15d54"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { AC 41 80 01 AC 41 80 00 AC 41 80 00 AC 41 C0 00 AC 41 80 01 }
        $a2 = { AC 41 80 00 AC 41 80 07 AC 41 80 00 AC 41 80 00 AC 41 80 00 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_de52ed44 {
    meta:
        id = "6mJNfDtkmJI2F9fFSvAhCK"
        fingerprint = "v1_sha256_95a60079a316016ca3f78f18e7920b962f5770bef4211dd70e37f45bbe069406"
        version = "1.0"
        date = "2023-05-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "c689a384f626616005d37a94e6a5a713b9eead1b819a238e4e586452871f6718"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 08 31 FF 89 7D CC 66 8C E8 66 85 C0 74 03 FF 45 CC FF 53 48 }
        $a2 = { B0 8F 45 C8 8D 45 B8 89 38 8D 4D C8 6A 04 57 6A 01 51 57 57 }
    condition:
        all of them
}

rule Windows_Trojan_Smokeloader_bf391fe0 {
    meta:
        id = "3NcpApo8Uj4z1UslP1qbvP"
        fingerprint = "v1_sha256_8a697596f8aa9a2af230b294c64ee844fcb593814a070ebf10e084c18e7f5ac7"
        version = "1.0"
        date = "2024-08-27"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "fe2489230d024f5e0e7d0da0210f93e70248dc282192c092cbb5e0eddc7bd528"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 8A 54 3C 18 0F B6 C2 03 F0 23 F1 8A 44 34 18 88 44 3C 18 88 54 34 18 0F B6 4C 3C 18 }
        $b = { 8D 87 77 05 00 00 50 8B 44 24 18 05 36 01 00 00 50 }
    condition:
        any of them
}

rule Windows_Trojan_Smokeloader_a01aa3ab {
    meta:
        id = "1sr6psNkfs7re6TeUyR687"
        fingerprint = "v1_sha256_385f93a98e71f8e78e2f916775bd8db182842c8439a2f15238780388b63e2e91"
        version = "1.0"
        date = "2024-08-27"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "3a189a736cfdfbb1e3789326c35cecfa901a2adccc08c66c5de1cac8e4c1791b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 83 A6 43 0C 00 00 00 83 A6 3F 0C 00 00 00 45 33 C9 45 8D 41 04 33 D2 33 C9 }
        $b = { 42 0F B6 14 0C 41 8D 04 12 44 0F B6 D0 42 8A 04 14 42 88 04 0C 42 88 14 14 42 0F B6 }
    condition:
        any of them
}

rule Windows_Trojan_Smokeloader_62eb5427 {
    meta:
        id = "HT2n7O2bkZohO2BmdKppt"
        fingerprint = "v1_sha256_e3c70731792a8fbf0b08443f6df3c42f44a548fa9d19be7ee98c677952600e5b"
        version = "1.0"
        date = "2024-08-27"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Smokeloader"
        reference_sample = "21e7fcce8ffb7826108800b6aee21d6b8ea9275975b639ed5ca9f8ddd747329e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { C7 45 FC 00 00 00 00 8B 45 08 03 40 3C 8B 40 78 03 45 08 50 8B 48 18 8B 50 20 03 55 08 }
        $b = { 8B 7D F4 89 F1 B8 19 04 00 00 F2 66 AF }
        $c = { C7 44 05 D0 53 6C 65 65 8B 45 C8 83 C0 04 89 45 C8 }
    condition:
        any of them
}

