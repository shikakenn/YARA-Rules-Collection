rule Linux_Cryptominer_Stak_05088561 {
    meta:
        id = "t9JXFRNeS7eYM9AvXFLxC"
        fingerprint = "v1_sha256_2b0f8a4efdfb13abcc2a1b43e9c39828ea1de6015fef0ef613bd754da5aa3e9a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CD 49 8D 4D 07 48 83 E1 F8 48 39 CD 73 55 49 8B 06 48 8B 50 08 48 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_ae8b98a9 {
    meta:
        id = "waqq7NQLCuatCaBhX3PGf"
        fingerprint = "v1_sha256_aade76488aa2f557de9082647153cca374a4819cd8e539ebba4bfef2334221b0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Stak"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D1 73 5A 49 8B 06 48 8B 78 08 4C 8B 10 4C 8D 4F 18 4D 89 CB 49 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_d707fd3a {
    meta:
        id = "5yUjdiKsbFPg7DWSjqazis"
        fingerprint = "v1_sha256_b825247372aace6e3ce0ff1d9685b6bb041b7277f8967d5f5926b49813cfadc9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C2 01 48 89 10 49 8B 55 00 48 8B 02 48 8B 4A 10 48 39 C8 74 9E 80 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_52dc7af3 {
    meta:
        id = "2LqmVTOKRr7WX6i9LwNdng"
        fingerprint = "v1_sha256_81998164f517b6f1ef72b10227cfff86aa8bbd2b4e2668f946c8ed59696ae74d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "a9c14b51f95d0c368bf90fb10e7d821a2fbcc79df32fd9f068a7fc053cbd7e83"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F9 48 89 D3 4D 8B 74 24 20 48 8D 41 01 4C 29 FB 4C 8D 6B 10 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_bb3153ac {
    meta:
        id = "1ZG0ZfNyN1t0SVDe9skoRi"
        fingerprint = "v1_sha256_e8516a24358b12863fe52c823ca67f0004457017334fe77dabf5f08d6bf2d907"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "5b974b6e6a239bcdc067c53cc8a6180c900052d7874075244dc49aaaa9414cca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6C 77 61 79 73 22 2C 20 22 6E 6F 5F 6D 6C 63 6B 22 2C 20 22 }
    condition:
        all of them
}

