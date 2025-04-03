rule Linux_Cryptominer_Generic_d7bd0e5d {
    meta:
        id = "2GoFYjAG78GyaQGy3sP3uP"
        fingerprint = "v1_sha256_1f87721fdfe58d029c0696bc99385a0052c771bc48b2c9ce01b72c3e42359654"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "afcfd67af99e437f553029ccf97b91ed0ca891f9bcc01c148c2b38c75482d671"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CF 99 67 D8 37 AA 24 80 F2 F3 47 6A A5 5E 88 50 F1 28 61 18 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_69e1a763 {
    meta:
        id = "1nuw3dFwjtuDSuOHvQynWS"
        fingerprint = "v1_sha256_d0dac8e2c9571d9e622c8c1250a54a7671ad1b9b00dba584c3741b714c22d8e0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b04d9fabd1e8fc42d1fa8e90a3299a3c36e6f05d858dfbed9f5e90a84b68bcbb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 43 08 49 89 46 08 48 8B 43 10 49 89 46 10 48 85 C0 74 8A F0 83 40 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_397a86bd {
    meta:
        id = "5sNSQqmQZl37W8rD5JNKeX"
        fingerprint = "v1_sha256_6b46a82d1aea0357f5a48c9ae1d93e3d4d31bd98b9c9b4e0b0d0629e7f159499"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "79c47a80ecc6e0f5f87749319f6d5d6a3f0fbff7c34082d747155b9b20510cde"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 4F 48 8B 75 00 48 8B 4D 08 4C 89 F7 48 8B 55 10 48 8B 45 18 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_37c3f8d3 {
    meta:
        id = "24XTrvfOSFnsbACH2AjFfY"
        fingerprint = "v1_sha256_e7bdd185ea4227b0960c3e677e7d8ac7488d53eaa77efd631be828b2ca079bb8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "efbddf1020d0845b7a524da357893730981b9ee65a90e54976d7289d46d0ffd4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F0 4C 01 F0 49 8B 75 08 48 01 C3 49 39 F4 74 29 48 89 DA 4C }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_28a80546 {
    meta:
        id = "5Jbg4nUpXyNNwEHiTwD5Cz"
        fingerprint = "v1_sha256_120e9f7cad0fc8aebd843374c0edca8cbb701882ab55a7f24aced1d80d8cd697"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "96cc225cf20240592e1dcc8a13a69f2f97637ed8bc89e30a78b8b2423991d850"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 72 59 D4 B5 63 E2 4D B6 08 EF E8 0A 3A B1 AD 1B 61 6E 7C 65 D1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9d531f70 {
    meta:
        id = "zH8PYsrWr9hcXYwuKYrOM"
        fingerprint = "v1_sha256_87d3cb7049975d52f2a6d6aa10e6b6d0d008d166ca5f9889ad1413a573d8b58e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 49 10 58 00 10 D4 34 80 08 30 01 20 02 00 B1 00 83 49 23 16 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_23a5c29a {
    meta:
        id = "5SAYZeKZZHG1Pv3bmwTngc"
        fingerprint = "v1_sha256_c2608e7ee73102e0737a859a18c5482877c6dc0e597d8a14d8d41f5e01a0b1f4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C1 48 29 D0 48 01 C0 4D 8B 39 48 29 C1 49 29 F8 48 8D 04 C9 4D 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_ea5703ce {
    meta:
        id = "2YFH8657r8vLb6CrTmwPSQ"
        fingerprint = "v1_sha256_bbf0191ecff24fd24376fd3dec2e96644188ca4d26b4ca4f087e212bae2eab85"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "bec6eea63025e2afa5940d27ead403bfda3a7b95caac979079cabef88af5ee0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 94 C0 EB 05 B8 01 00 00 00 44 21 E8 48 8B 4C 24 08 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_6a4f4255 {
    meta:
        id = "5t6FGsX9KJey3Ak3j9hI56"
        fingerprint = "v1_sha256_133290dc7423174bb3b41b152bab038d118b47baaca52705b66fd9be01692a03"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FD 48 8D 5D 01 4C 8D 14 1B 48 C1 E3 05 4C 01 EB 4D 8D 7A FF F2 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9088d00b {
    meta:
        id = "2KX6sJgHc48qf8eafS3JpZ"
        fingerprint = "v1_sha256_3ebc8cb6d647138e72194528dafc644c90222440855d657ec50109f11ff936da"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "8abb2b058ec475b0b6fd0c994685db72e98d87ee3eec58e29cf5c324672df04a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 2C 1C 77 16 48 8B 44 24 08 64 48 33 04 25 28 00 00 00 75 24 48 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_71024c4a {
    meta:
        id = "4TIbGtyuWeVTyPZ4kkFw6t"
        fingerprint = "v1_sha256_0c66a3388fe8546ae180e52d50ef05a28755d24e47b3b56f390d5c6fcb0b89eb"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "afe81c84dcb693326ee207ccd8aeed6ed62603ad3c8d361e8d75035f6ce7c80f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 46 08 48 89 45 08 48 8B 46 10 48 85 C0 48 89 45 10 74 BC F0 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_d81368a3 {
    meta:
        id = "2vnQH6G83GQXujaSZ7zskU"
        fingerprint = "v1_sha256_0e30c9ebd8f2d3a489180f114daf91a3655ce9075ae25ea3d6ef5be472d7721a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "71225e4702f2e0a0ecf79f7ec6c6a1efc95caf665fda93a646519f6f5744990b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CB 49 C1 E3 04 49 01 FB 41 8B 13 39 D1 7F 3F 7C 06 4D 3B 43 08 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_97e9cebe {
    meta:
        id = "4zFbELrlANeXqiWnz85Gkr"
        fingerprint = "v1_sha256_8aad31db2646fb9971b9af886e30f6c5a62a9c7de86cb9dc9e1341ac3b7762eb"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b4ff62d92bd4d423379f26b37530776b3f4d927cc8a22bd9504ef6f457de4b7a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 04 25 28 00 00 00 48 89 44 24 58 31 C0 49 83 FF 3F 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_98ff0f36 {
    meta:
        id = "5RFqaHDN7XjZTbm0yo4DUD"
        fingerprint = "v1_sha256_60f17855b08cfc51e497003cbb5ed25d9168fb29c57d8bfd7105b9b5e714e3a1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "4c14aaf05149bb38bbff041432bf9574dd38e851038638aeb121b464a1e60dcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 A8 8B 00 89 C2 48 8B 45 C8 48 01 C2 8B 45 90 48 39 C2 7E 08 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1512cf40 {
    meta:
        id = "5qRv8vgkqYhFCJkIaLYskl"
        fingerprint = "v1_sha256_0d43e6a4bd5036c2b6adb61f2d7b11e625c20e9a3d29242c7c34cfc7708561be"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "fc063a0e763894e86cdfcd2b1c73d588ae6ecb411c97df2a7a802cd85ee3f46d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C4 10 5B C3 E8 35 A7 F6 FF 0F 1F 44 00 00 53 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_0d6005a1 {
    meta:
        id = "6yf0ZOmoSrNrlBtzYzz3uJ"
        fingerprint = "v1_sha256_c3fd32e7582f0900b94fe3ba6b6bcdf238f78e2e343d70d5b0196a968a41cf26"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "230d46b39b036552e8ca6525a0d2f7faadbf4246cdb5e0ac9a8569584ef295d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 79 73 00 6E 6F 5F 6D 6C 63 6B 00 77 61 72 6E 00 6E 65 76 65 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e1ff020a {
    meta:
        id = "lCY8xKdSYYUvU6xagmss0"
        fingerprint = "v1_sha256_be801989b9770f3b70217bd5f13795b5dd0b516209f631d900b6647e0afe8d98"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "5b611898f1605751a3d518173b5b3d4864b4bb4d1f8d9064cc90ad836dd61812"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F B6 4F 3D 0B 5C 24 F4 41 C1 EB 10 44 0B 5C 24 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_102d6f7c {
    meta:
        id = "24Tf1ODYDA6O5Frn0UAfsB"
        fingerprint = "v1_sha256_52966eaaef5522e711dc89bd796b1e12019a8485ee789e8d5112d86f7e630170"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "bd40c2fbf775e3c8cb4de4a1c7c02bc4bcfa5b459855b2e5f1a8ab40f2fb1f9e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 70 D2 AA C5 F9 EF D2 C5 F1 EF CB C5 E1 73 FB 04 C4 E3 79 DF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9c8f3b1a {
    meta:
        id = "2gFjnU7hD8ePWslA9RfFvT"
        fingerprint = "v1_sha256_f7ab9990b417c1c81903dcb7adaae910d20ea7fce6689d4846dd6002bea3e721"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "74d8344139c5deea854d8f82970e06fc6a51a6bf845e763de603bde7b8aa80ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6F 67 31 70 00 6C 6F 67 32 66 00 6C 6C 72 6F 75 6E 64 00 73 71 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_76cb94a9 {
    meta:
        id = "19JlRdCkR1icYIGU8dC6Gb"
        fingerprint = "v1_sha256_758ee41048c94576e7a872bfdacc6b6f2be3d460169905c876585037e11fdaa8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8C 24 98 00 00 00 31 C9 80 7A 4A 00 48 89 74 24 18 48 89 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_616afaa1 {
    meta:
        id = "5UE5ImawKRssjydNRUT6QB"
        fingerprint = "v1_sha256_53a309a6a274558e4ae8cfa8f3e258f23dc9ceafab3be46351c00d24f5d790ec"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "0901672d2688660baa26fdaac05082c9e199c06337871d2ae40f369f5d575f71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4B 04 31 C0 41 8B 14 07 89 14 01 48 83 C0 04 48 83 F8 14 75 EF 4C 8D 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_18af74b2 {
    meta:
        id = "yZfXwHQfMbQX39OPoCY1n"
        fingerprint = "v1_sha256_d8ec9bd01fcabdd4a80e07287ecc85026007672bbc3cd2d4cbb2aef98da88ed5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "52707aa413c488693da32bf2705d4ac702af34faee3f605b207db55cdcc66318"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 70 6F 77 00 6C 6F 67 31 70 00 6C 6F 67 32 66 00 63 65 69 6C 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1b76c066 {
    meta:
        id = "3eNrJ0jBJUNkrqFY1iUqw8"
        fingerprint = "v1_sha256_be239bc14d1adf05a5c6bf2b2557551566330644a049b256a7a5c0ab9549bd06"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "f60302de1a0e756e3af9da2547a28da5f57864191f448e341af1911d64e5bc8b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0C 14 89 0C 10 48 83 C2 04 48 83 FA 20 75 EF 48 8D 8C 24 F0 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b6ea5ee1 {
    meta:
        id = "6h1RpuWmYtHFprfOX6WWC0"
        fingerprint = "v1_sha256_529119e07aa0243afddc3141dc441c314c3f75bdf3aee473b8bb7749c95fa78a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 47 20 49 8D 77 20 4C 89 74 24 10 4C 89 6C 24 18 4C 89 64 24 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_050ac14c {
    meta:
        id = "6YPEHRz4GPFIYnswFQlCzh"
        fingerprint = "v1_sha256_c34b0ff3ce867a76ef57fad7642de7916fa7baebf1a2a8d514f7b74be7231fd4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 47 08 49 3B 47 10 74 3C 48 85 C0 74 16 48 8B 13 48 89 10 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_df937caa {
    meta:
        id = "64lAVWcL1ljYTMfcptleiw"
        fingerprint = "v1_sha256_d76a6008576687088f28674fb752e1a79ad2046e0208a65c21d0fcd284812ad8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 04 62 20 0A 10 02 0A 14 60 29 00 02 0C 24 14 60 7D 44 01 70 01 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e9ff82a8 {
    meta:
        id = "7T48dvI3Q1GckJvSSPJ83B"
        fingerprint = "v1_sha256_9309aaad6643fa212bb04ce8dc7d24978839fe475f17d36e3b692320563b6fad"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "62ea137e42ce32680066693f02f57a0fb03483f78c365dffcebc1f992bb49c7a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D9 4D 01 CA 4C 89 74 24 D0 4C 8B 74 24 E8 4D 31 D4 49 C1 C4 20 48 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_a5267ea3 {
    meta:
        id = "514PqMEckygdwz5FRWUVwj"
        fingerprint = "v1_sha256_081633b5aa0490dbffcc0b8ab9850b59dbbd67d947c0fe68d28338a352e94676"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b342ceeef58b3eeb7a312038622bcce4d76fc112b9925379566b24f45390be7d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EE 6A 00 41 B9 01 00 00 00 48 8D 4A 13 4C 89 E7 88 85 40 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_4e9075e6 {
    meta:
        id = "6t1SuqYOCsn8qsa0Bd3fxk"
        fingerprint = "v1_sha256_fe117f65666b9eac19fa588ee631f9be7551a3a9e3695b7ecbb77806658678aa"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "098bf2f1ce9d7f125e1c9618f349ae798a987316e95345c037a744964277f0fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 2C 24 74 67 48 89 5C 24 18 4C 89 6C 24 20 4C 89 FB 4D 89 E5 4C 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_3a8d0974 {
    meta:
        id = "1wTpL7u09dKBJTZdQ2IyWH"
        fingerprint = "v1_sha256_7039d461d8339d635a543fae2c6dbea284ce1b727d6585b69d8d621c603f37ac"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "193fe9ea690759f8e155458ef8f8e9efe9efc8c22ec8073bbb760e4f96b5aef7"
        threat_name = "Linux.Cryptominer.Generic"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 07 41 89 34 06 48 83 C0 04 48 83 F8 20 75 EF 8B 42 D4 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b9e6ffdf {
    meta:
        id = "41WcSl7Kdp4chKeIJAmYeL"
        fingerprint = "v1_sha256_57d5b3eb5812a849d04695bdb1fb728a5ebd3bf5201ac3e7f36d37af0622eec2"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "c0f3200a93f1be4589eec562c4f688e379e687d09c03d1d8850cc4b5f90f192a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 D8 48 83 C4 20 5B C3 0F 1F 00 BF ?? ?? 40 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_7ef74003 {
    meta:
        id = "3ADg2HFL2AmRs3hGbgejUM"
        fingerprint = "v1_sha256_1bde07dbb88357fcc02171512725be94d9fc0427c03afb2d59fbd0658c5d8e2e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "a172cfecdec8ebd365603ae094a16e247846fdbb47ba7fd79564091b7e8942a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 56 45 31 F6 41 55 49 89 F5 41 54 44 8D 67 01 55 4D 63 E4 53 49 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1d0700b8 {
    meta:
        id = "3P9L5TXoyYqq33FUjd4iWS"
        fingerprint = "v1_sha256_a24264cb071d269c82718aed5bc5c6c955e1cb2c7a63fe74d4033bfa6adf8385"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 30 42 30 42 00 22 22 03 5C DA 10 00 C0 00 60 43 9C 64 48 00 00 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_55beb2ee {
    meta:
        id = "6Yf0zK4ZERv8wkONcMXMJb"
        fingerprint = "v1_sha256_8a31b4866100b35d559d50f5db6f80d51bced93f9aac3f0d2d1de71ba692a3c5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "edda1c6b3395e7f14dd201095c1e9303968d02c127ff9bf6c76af6b3d02e80ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 FC 00 00 00 8B 84 24 C0 00 00 00 0F 29 84 24 80 00 00 00 0F 11 94 24 C4 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_fdd7340f {
    meta:
        id = "56vpOc5ahb0Xl87Qs4nCR3"
        fingerprint = "v1_sha256_fd39ba5cf050d23de0889feefa9cd74dfb6385a09aa9dba90dc1d5d6cb020867"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EA 48 89 DE 48 8D 7C 24 08 FF 53 18 48 8B 44 24 08 48 83 78 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e36a35b0 {
    meta:
        id = "3gzCcrNKSbM01mTL0WAfMF"
        fingerprint = "v1_sha256_0572f584746a2af6f545798b25445fd4e764a9eecc01b7476e5c1af631eb314a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "ab6d8f09df67a86fed4faabe4127cc65570dbb9ec56a1bdc484e72b72476f5a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 71 F2 08 66 0F EF C1 66 0F EF D3 66 0F 7F 44 24 60 66 0F 7F 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_6dad0380 {
    meta:
        id = "16A416Y2RhVXfPhZ0KBCp4"
        fingerprint = "v1_sha256_b305448d5517212adb7586e7af12842095e1a263520511329e40f0865fe4f81b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "628b1cc8ccdbe2ae0d4ef621da047e07e2532d00fe3d4da65f0a0bcab20fb546"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 C1 E6 05 48 01 C6 48 39 F1 74 05 49 89 74 24 08 44 89 E9 48 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e73f501e {
    meta:
        id = "2NTcGkUjYj10Fmmo5w9U4j"
        fingerprint = "v1_sha256_2f6187f3447f9409485e9e8aa047114aa3c38bcc338106c3ed8680152dff121a"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "2f646ced4d05ba1807f8e08a46ae92ae3eea7199e4a58daf27f9bd0f63108266"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 03 51 8A 92 FF F3 20 01 DE 63 AF 8B 54 73 0A 65 83 64 88 60 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_5e56d076 {
    meta:
        id = "4JMPVT6Rs2OFcuJoXVKZEj"
        fingerprint = "v1_sha256_c8e2ebcffe8a169c2cc311c95538b674937fa87e06d2946a6ed3b0c1f039f7fc"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "32e1cb0369803f817a0c61f25ca410774b4f37882cab966133b4f3e9c74fac09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 71 18 4C 89 FF FF D0 48 8B 84 24 A0 00 00 00 48 89 43 60 48 8B 84 24 98 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_54357231 {
    meta:
        id = "15YAfnDCR79W32bsbFZj69"
        fingerprint = "v1_sha256_a895c9fd124d6bd55748093c3ef54606e5692285260aa21bd70dca02126239d2"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 73 F2 06 C5 F9 EB C2 C4 E3 79 16 E0 02 C4 E3 79 16 E2 03 C5 F9 70 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_467c4d46 {
    meta:
        id = "1OsPrGPi5k7efWyY1wiLjo"
        fingerprint = "v1_sha256_b28f871365c1fa6315b1c2fc6698bdd224961972cd578db05c311406c239ac22"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 49 8B 77 08 48 21 DE 4C 39 EE 75 CE 66 41 83 7F 1E 04 4C 89 F5 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e0cca9dc {
    meta:
        id = "1SfRzU4bbZrduL0ymZqNQF"
        fingerprint = "v1_sha256_fa4089f74fc78e99427b4e8eda9f8348e042dc876c7281a4a2173c83076bfbd2"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 24 40 48 8D 94 24 C0 00 00 00 F3 41 0F 6F 01 48 89 7C 24 50 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_36e404e2 {
    meta:
        id = "2lar20XTUqIRp9VioSN6RL"
        fingerprint = "v1_sha256_d38cc5714721c0b00cfa47cb9828fd76ff57ec8180e5cfe1fec67a092dd87904"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 61 6C 73 65 20 70 6F 73 69 74 69 76 65 29 1B 5B 30 6D 00 44 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_947dcc5e {
    meta:
        id = "3KMjmPXaNQhdxdVxvbY37S"
        fingerprint = "v1_sha256_c4aac006561386fbfe0fa0fe3df6b6798d2915a3dbfb5384583ebf9b2f413115"
        version = "1.0"
        date = "2024-04-19"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "7c5a6ac425abe60e8ea5df5dfa8211a7c34a307048b4e677336b735237dcd8fd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 28 00 00 0A 30 51 9F E5 04 20 94 E5 04 30 A0 E1 38 00 44 E2 00 40 94 E5 00 40 82 E5 04 20 93 E5 04 20 84 E5 0C 20 13 E5 00 30 83 E5 04 00 12 E3 04 30 83 E5 06 00 00 0A 04 10 C2 E3 08 00 12 E3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b4c2d007 {
    meta:
        id = "278XoCEC7G6dZpyA67X9Tq"
        fingerprint = "v1_sha256_cb52d9233028918210b8bd3959a6649d75b5c6873befff0cf62d9e71dfecc302"
        version = "1.0"
        date = "2024-04-19"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "e1e518ba226d30869e404b92bfa810bae27c8b1476766934961e80c44e39c738"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FD 03 00 91 F3 53 01 A9 F4 03 00 AA 20 74 40 F9 60 17 00 B4 20 10 42 79 F3 03 01 AA F9 6B 04 A9 40 17 00 34 62 62 40 39 F5 5B 02 A9 26 10 40 39 F7 63 03 A9 63 12 40 B9 FB 73 05 A9 3B A0 03 91 }
    condition:
        all of them
}

