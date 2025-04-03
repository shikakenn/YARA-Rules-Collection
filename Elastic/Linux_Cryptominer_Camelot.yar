rule Linux_Cryptominer_Camelot_9ac1654b {
    meta:
        id = "779LCPDXti7c9KQnBi5QJQ"
        fingerprint = "v1_sha256_5de1f43803f3d3b94149ea39ed961e7b9a1ad86c15c5085e2e0a5f9c314e98ff"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CD 41 C1 CC 0B 31 D1 31 E9 44 89 D5 44 31 CD C1 C9 07 41 89 E8 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_dd167aa0 {
    meta:
        id = "4wzmb1vVgZkVTrhgxTYf6T"
        fingerprint = "v1_sha256_88be4fbb337fa866e126021b40a01d86a33029071af7efc289a8c5490d21ea8a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E7 F2 AE 4C 89 EF 48 F7 D1 48 89 CE 48 89 D1 F2 AE 48 89 C8 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_b25398dd {
    meta:
        id = "7UUzOYp7r4s3E7hn36Gfzz"
        fingerprint = "v1_sha256_e7fdb3c573909e8f197417278a6d333cc3743b05257d81fed46769b185354183"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "6fb3b77be0a66a10124a82f9ec6ad22247d7865a4d26aa49c5d602320318ce3c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 04 76 48 8B 44 07 23 48 33 82 C0 00 00 00 48 89 44 24 50 49 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_6a279f19 {
    meta:
        id = "45ZUFlVP0stoKKbQy1fmC3"
        fingerprint = "v1_sha256_91e3c0d96fe5ab9c61b38f01d39639020ec459bec6348b1f87a2c5b1a874e24a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "5b01f72b2c53db9b8f253bb98c6584581ebd1af1b1aaee62659f54193c269fca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 F3 89 D6 48 83 EC 30 48 89 E2 64 48 8B 04 25 28 00 00 00 48 89 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_4e7945a4 {
    meta:
        id = "7f5o9PciiTcsbXGAyMRLab"
        fingerprint = "v1_sha256_aebc544076954fcce917e026467a8828b18446ce7c690b4c748562e311b7d491"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "b7504ce57787956e486d951b4ff78d73807fcc2a7958b172febc6d914e7a23a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E5 48 81 EC A0 00 00 00 48 89 7D F0 48 8B 7D F0 48 89 F8 48 05 80 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_29c1c386 {
    meta:
        id = "4X0Kd0aVxZNnRTRgXOFnrY"
        fingerprint = "v1_sha256_1a3a9065cbb59658c06dfbfc622ccd2e577e988370ffe47848a5859f96db4e24"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 65 20 62 72 61 6E 63 68 00 00 00 49 67 6E 6F 72 69 6E 67 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_25b63f54 {
    meta:
        id = "PGyo2ws6VfmiKqugtkCWl"
        fingerprint = "v1_sha256_640ffe2040e382ad536c1b6947e05f8c25ff82897ef7ac673a7676815856a346"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 6F 39 66 41 0F 6F 32 66 4D 0F 7E C3 66 44 0F D4 CB 66 45 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_73e2373e {
    meta:
        id = "2hvu50BApMJgOBhlgxI7UB"
        fingerprint = "v1_sha256_2377da6667860dc7204760ee64213cba95909c9181bd1a3ea96c3ad29988c9f7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 F8 48 83 7D F8 00 74 4D 48 8B 55 80 48 8D 45 A0 48 89 D6 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_b8552fff {
    meta:
        id = "4qbLXFQbR9PQughiJdcB7o"
        fingerprint = "v1_sha256_476b800422b6d98405d8bde727bb589c5cae36723436b269beaa65381b3d0abe"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 18 8B 44 24 1C 8B 50 0C 83 E8 04 8B 0A FF 74 24 28 FF 74 24 28 FF 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_83550472 {
    meta:
        id = "4jOMqYyeV4VrdLcnp2KGyb"
        fingerprint = "v1_sha256_f62d4a2a7dfb312b2e362844bfa29bd4453a05f31b4f72550ef29ff40ed6fb9d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FA 48 8D 4A 01 48 D1 E9 48 01 CA 48 29 F8 48 01 C3 49 89 C4 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_8799d8d6 {
    meta:
        id = "4ygrTirnChxBBWfQXCNY3A"
        fingerprint = "v1_sha256_4bcd7931aeed09069d5dd248a66f119a2bdf628e03b9abed9ee2de59a149c2bc"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "4a6d98eae8951e5b9e0a226f1197732d6d14ed45c1b1534d3cdb4413261eb352"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 72 56 66 48 32 37 48 4D 5A 75 6D 74 46 75 4A 72 6D 48 47 38 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_0f7c5375 {
    meta:
        id = "6h2w5XFtatcLsTUjB7eoN0"
        fingerprint = "v1_sha256_05f4b16a7e4c7ffbc6b8a2f60050a4ac1d05d9efbe948e2da689055f6383cf82"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "e75be5377ad65abdc69e6c7f9fe17429a98188a217d0ca3a6f40e75c4f0c07e8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 7F 48 89 85 C0 00 00 00 77 08 48 83 85 C8 00 00 00 01 31 F6 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_87639dbd {
    meta:
        id = "2wht7FQOmlZd5IquWBqBme"
        fingerprint = "v1_sha256_b81af8c9baee999b91e63f97d5a46451d9960487b25b04079df5539f857be466"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 00 48 83 C2 01 48 89 EF 48 89 53 38 FF 50 18 48 8D 7C 24 30 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_cdd631c1 {
    meta:
        id = "xEtvPmA7Rnsny4AgRbIUf"
        fingerprint = "v1_sha256_5e4b26a74fc3737c068917c7c1228048f885ac30fc326a2844611f7e707d1300"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "91549c171ae7f43c1a85a303be30169932a071b5c2b6cf3f4913f20073c97897"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 5F 5A 4E 35 78 6D 72 69 67 35 50 6F 6F 6C 73 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_209b02dd {
    meta:
        id = "7lq7S1PSXXn3kj7xqPTgDc"
        fingerprint = "v1_sha256_5cadc955242d4b7d5fd4365a0b425051d89c905e3d49ea03967150de0020225c"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "60d33d1fdabc6b10f7bb304f4937051a53d63f39613853836e6c4d095343092e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 31 F5 44 0B 5C 24 F4 41 C1 EA 10 44 0B 54 24 }
    condition:
        all of them
}

