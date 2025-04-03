rule Linux_Trojan_Mirai_268aac0b {
    meta:
        id = "3PaTTyj22o44zddJpyxFqh"
        fingerprint = "v1_sha256_6eae3aba35d3379fa194b66a1b4e0d78d0d0b88386cd4ea5dfeb3c072642c7ba"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 18 0F B7 44 24 20 8B 54 24 1C 83 F9 01 8B 7E 0C 89 04 24 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5f2abe2 {
    meta:
        id = "69h1TzGBvcYPB1mfMiIFHU"
        fingerprint = "v1_sha256_169e7e5d1a7ea8c219464e22df9be8bc8caa2e78e1bc725674c8e0b14f6b9fc5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 56 41 89 FE 40 0F B6 FF 41 55 49 89 F5 BE 08 00 00 00 41 54 41 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1cb033f3 {
    meta:
        id = "qskJMUpHsp7NSkcwtpYMZ"
        fingerprint = "v1_sha256_ebaf45ce58124aa91b07ebb48779e6da73baa0b80b13e663c13d8fb2bb47ad0d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C3 EB 06 8A 46 FF 88 47 FF FF CA 48 FF C7 48 FF C6 83 FA FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fa3ad9d0 {
    meta:
        id = "6guSKHGIaSQw4hGBEdAeDy"
        fingerprint = "v1_sha256_5890c85872ea4508e673235b20b481972f613f6e5f9564c0237c458995532347"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CB 08 C1 CB 10 66 C1 CB 08 31 C9 8A 4F 14 D3 E8 01 D8 66 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0cb1699c {
    meta:
        id = "3nACsYpsqOvgpz3tsclUgW"
        fingerprint = "v1_sha256_97307f583240290de2bfc663b99f8dcdedace92885bd3e0c0340709b94c0bc2a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 10 0F B7 02 83 E9 02 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6f021787 {
    meta:
        id = "3cDfdElC1Aqea2fl07QzjL"
        fingerprint = "v1_sha256_7e8062682a0babbaa3c00975807ba9fc34c465afde55e4144944e7598f0ea1fd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "88183d71359c16d91a3252085ad5a270ad3e196fe431e3019b0810ecfd85ae10"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 D4 66 89 14 01 0F B6 45 D0 48 63 D0 48 89 D0 48 01 C0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1e0c5ce0 {
    meta:
        id = "36DhCIaleuPXNtydaetxQs"
        fingerprint = "v1_sha256_591cc3ef6932bf990f56c932866b34778e8eccd0e343f9bd6126eb8205a12ecc"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5b1f95840caebf9721bf318126be27085ec08cf7881ec64a884211a934351c2d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4C 24 54 31 F6 41 B8 04 00 00 00 BA 03 00 00 00 C7 44 24 54 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_22965a6d {
    meta:
        id = "1SLUeluU2BBmFXONWfD9aO"
        fingerprint = "v1_sha256_6b2a46694edf709d28267268252cfe95d88049b7dca854059cfe44479ada7423"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "09c821aa8977f67878f8769f717c792d69436a951bb5ac06ce5052f46da80a48"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E6 4A 64 2B E4 82 D1 E3 F6 5E 88 34 DA 36 30 CE 4E 83 EC F1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_4032ade1 {
    meta:
        id = "5t2f6BWubMWmnX6KnYdEW1"
        fingerprint = "v1_sha256_9c5e24c4efd4035408897f638d3579c3798139fd18178cee4a944b49c13e1532"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "6150fbbefb916583a0e888dee8ed3df8ec197ba7c04f89fb24f31de50226e688"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 0C 67 56 55 4C 06 87 DE B2 C0 79 AE 88 73 79 0C 7E F8 87 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b14f4c5d {
    meta:
        id = "33TD5IIbHTr2rmCIXfT3vc"
        fingerprint = "v1_sha256_1a2114a7b397c850d732940a0e154bc04fbee1fdc12d343947b343b9b27a8af1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 53 31 DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 15 66 8B 02 83 E9 02 25 FF FF 00 00 83 C2 02 01 C3 83 F9 01 77 EB 49 75 05 0F BE 02 01 C3 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c8385b81 {
    meta:
        id = "9NRJTxu8D5pp7kMQu01Ue"
        fingerprint = "v1_sha256_4ff1f0912fb92e7ac5af49e1738dac897ff1f0a118d8ff905da45b0a91b3f4a7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "3d27736caccdd3199a14ce29d91b1812d1d597a4fa8472698e6df6ef716f5ce9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8D 74 26 00 89 C2 83 ED 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_122ff2e6 {
    meta:
        id = "2Pm1I0mrq4kenNSXIBLl0f"
        fingerprint = "v1_sha256_62884309b9095cdd6219c9ef6cd77a0f712640d8a1db4afe5b1d01f4bbe5acc2"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c7dd999a033fa3edc1936785b87cd69ce2f5cac5a084ddfaf527a1094e718bc4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 EB 15 89 F0 83 C8 01 EB 03 8B 5B 08 3B 43 04 72 F8 8B 4B 0C 89 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_26cba88c {
    meta:
        id = "3v99Emy6wD3cP3SZHhzplp"
        fingerprint = "v1_sha256_bb5a0f9e68655556ab9fccc27d11bf7828c299720bb67948455579d6a7eb2a9f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4b4758bff3dcaa5640e340d27abba5c2e2b02c3c4a582374e183986375e49be8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F6 41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_93fc3657 {
    meta:
        id = "4mShMgpzGEaN3yrrLhmOdQ"
        fingerprint = "v1_sha256_0b5278feddd00b0b24ca735bf7cd1440379c6ce5aca6d2a6f38c9fdcedcb3c0d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 89 44 24 60 89 D1 31 C0 8B 7C 24 28 FC F3 AB 89 D1 8B 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7c88acbc {
    meta:
        id = "5AFv6101Ht9ka1j3HAN2XH"
        fingerprint = "v1_sha256_76373f8e09b7467ac5d36e8baad3025a57568e891434297e53f2629a72cf8929"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = "[Cobalt][%s][%s][%s][%s]"
    condition:
        all of them
}

rule Linux_Trojan_Mirai_804f8e7c {
    meta:
        id = "11UliLHjVDQ9awwjxeLG59"
        fingerprint = "v1_sha256_711d74406d9b0d658b3b29f647bd659699ac0af9cd482403122124ec6054f1ec"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 31 ED 81 E1 FF 00 00 00 89 4C 24 58 89 EA C6 46 04 00 C1 FA 1F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a2d2e15a {
    meta:
        id = "1wec6rxlGCDcS8bpRIxaxy"
        fingerprint = "v1_sha256_c76fe953c4a70110346a020f2b27c7e79f4ad8a24fd92ac26e5ddd1fed068f65"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "567c3ce9bbbda760be81c286bfb2252418f551a64ba1189f6c0ec8ec059cee49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 42 F0 41 83 F8 01 76 5F 44 0F B7 41 10 4C 01 C0 44 8D 42 EE 41 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5946f41b {
    meta:
        id = "6hQ4vD2333r0SspY8Ro4Yt"
        fingerprint = "v1_sha256_43691675db419426413ccc24aa9dfe94456fa1007630652b08a625eafd1f17b8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f0b6bf8a683f8692973ea8291129c9764269a6739650ec3f9ee50d222df0a38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 59 08 AA 3A 4C D3 6C 2E 6E F7 24 54 32 7C 61 39 65 21 66 74 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_da4aa3b3 {
    meta:
        id = "6APycbH2YkCuD38JqrUSI4"
        fingerprint = "v1_sha256_84ddc505d2e2be955b88a0fe3b78d435f73c0a315b513e105933e84be78ba2ad"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "dbc246032d432318f23a4c1e5b6fcd787df29da3bf418613f588f758dcd80617"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 D0 C1 E0 03 89 C2 8B 45 A0 01 D0 0F B6 40 14 3C 1F 77 65 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_70ef58f1 {
    meta:
        id = "2BNsSEhoA3WvuFNy9Ur9lh"
        fingerprint = "v1_sha256_3ad201d643e8f93a6f9075c03a76020d78186702a19bf9174b08688a2e94ef5c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 D0 8B 19 01 D8 0F B6 5C 24 10 30 18 89 D0 8B 19 01 D8 0F B6 5C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ea584243 {
    meta:
        id = "oqvDPfzpPhwl4l5882jP5"
        fingerprint = "v1_sha256_34c6f800c849c295797cdd971fb4f3d16d680530f9a98c291388345569708208"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C 81 FA }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_564b8eda {
    meta:
        id = "1WFNyjsaMAGlA00OUjD3J5"
        fingerprint = "v1_sha256_4bf11492f480911629623250146554f2456f3a527f5f80402ef74b22c1460462"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "ff04921d7bf9ca01ae33a9fc0743dce9ca250e42a33547c5665b1c9a0b5260ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C1 83 FE 01 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7e9f85fb {
    meta:
        id = "2kqyTQ2tVgotJEMInft2UQ"
        fingerprint = "v1_sha256_f4ce912e190bc5dcb56541f54ba8e47b6103c482bdc7e83b44693d2c066c0170"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4333e80fd311b28c948bab7fb3f5efb40adda766f1ea4bed96a8db5fe0d80ea1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 85 50 FF FF FF 0F B6 40 04 3C 07 75 79 48 8B 85 50 FF FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3a85a418 {
    meta:
        id = "6mmW3fUhoDljCx3pk5Ga9h"
        fingerprint = "v1_sha256_bd7fe497fb2557c9e9c26ec90e783f03cbbc9bdaa8d20b364ce65edf6c1e5fa3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "86a43b39b157f47ab12e9dc1013b4eec0e1792092d4cef2772a21a9bf4fc518a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 D8 66 C1 C8 08 C1 C8 10 66 C1 C8 08 66 83 7C 24 2C FF 89 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_24c5b7d6 {
    meta:
        id = "58xDUZ0zJxFSHfyE4VxKdi"
        fingerprint = "v1_sha256_f790f6b8fcf932773054525ed74a3f15998d91a2626ae9c56486de8dabc2035c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7c2f8ba2d6f1e67d1b4a3a737a449429c322d945d49dafb9e8c66608ab2154c4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 38 1C 80 FA 3E 74 25 80 FA 3A 74 20 80 FA 24 74 1B 80 FA 23 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_99d78950 {
    meta:
        id = "6RkbIuJL9sWuzDUqjkd1it"
        fingerprint = "v1_sha256_bfd628a9973f85ed0a8be2723c7ff4bd028af00ea98c9cbcde9df6aabcf394b2"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 89 C3 80 BC 04 83 00 00 00 20 0F 94 C0 8D B4 24 83 00 00 00 25 FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3fe3c668 {
    meta:
        id = "1z48TV9IzWoD8My1m1EyIY"
        fingerprint = "v1_sha256_e75b2dca7de7d9f31a0ae5940dc45d0e6d0f1ca110b5458fc99912400da97bde"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 84 C0 0F 95 C0 48 FF 45 E8 84 C0 75 E9 8B 45 FC C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_eedfbfc6 {
    meta:
        id = "6LCO7th9maYQcYJ8o5TgLG"
        fingerprint = "v1_sha256_949b32db1a00570fc84fbbe510f57f6e898d089efd3fedbd7719f8059021b6bc"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "b7342f7437a3a16805a7a8d4a667e0e018584f9a99591413650e05d21d3e6da6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 7C 39 57 52 AC 57 A8 CE A8 8C FC 53 A8 A8 0E 33 C2 AA 38 14 FB 29 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6d96ae91 {
    meta:
        id = "31ZEB9eRlqIhB4Z7s2k5ns"
        fingerprint = "v1_sha256_43b0ac7090620eb6c892f1105778c395bf18f5ac309ce1b2d9015b5abccbfc2a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "e3a1d92df6fb566e09c389cfb085126d2ea0f51a776ec099afb8913ef5e96f9b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 00 00 C1 00 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d8779a57 {
    meta:
        id = "48pwOqmKbGRMEWNNzlVZnt"
        fingerprint = "v1_sha256_2154786bbb6dbcc280aaa9e2b75106b585d04c7c85f6162f441c81dc54663cb3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B6 FF 41 89 D0 85 FF 74 29 38 56 08 74 28 48 83 C6 10 31 D2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3e72e107 {
    meta:
        id = "5kummCNRIiH6K0ic29NKht"
        fingerprint = "v1_sha256_ba0ba56ded8977502ad9f8a1ceebd30efbff964d576bbfeedff5761f0538d8f0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "57d04035b68950246dd152054e949008dafb810f3705710d09911876cd44aec7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 85 C0 BA FF FF FF FF 74 14 8D 65 F4 5B 5E 5F 89 D0 5D C3 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5c62e6b2 {
    meta:
        id = "5UESKHI45utgddBXl4Cjru"
        fingerprint = "v1_sha256_6505c4272f0f7c8c5f2d3f7cefdc3947c4015b0dfd94efde4357a506af93a99d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF C1 83 F9 05 7F 14 48 63 C1 48 89 94 C4 00 01 00 00 FF C6 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c5430ff9 {
    meta:
        id = "22bUToWwOQimsH1KjwpPDR"
        fingerprint = "v1_sha256_8c385980560cd4b24e703744b57a9d5ea1bca8fbeea066e98dd4b40009e56104"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5676773882a84d0efc220dd7595c4594bc824cbe3eeddfadc00ac3c8e899aa77"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 FC F3 A6 0F 97 C2 0F 92 C0 38 C2 75 29 83 EC 08 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_402adc45 {
    meta:
        id = "pNz3FOzfTWmKsqG48xJT9"
        fingerprint = "v1_sha256_dab879d57507d5e119ddf4ce6ed33570c74f185a2260e97a7ec1d6c844943e5d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C3 EB DF 5A 5B 5D 41 5C 41 5D C3 41 57 41 56 41 55 41 54 55 53 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a39dfaa7 {
    meta:
        id = "9bybn0Z7kN9DzwT337T7U"
        fingerprint = "v1_sha256_98fde36fc412b6aa50c80c12118975a6bf754a9fba94f1cc3cdeed22565d6b0d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 6C 72 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e3e6d768 {
    meta:
        id = "2rWBLKrDXTcxbg7sd4Oqwh"
        fingerprint = "v1_sha256_b848c7200f405d77553d661a6c49fb958df225875957ead35b35091995f307d1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "b505cb26d3ead5a0ef82d2c87a9b352cc0268ef0571f5e28defca7131065545e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 7E 14 48 89 DF 48 63 C8 4C 89 E6 FC F3 A4 41 01 C5 48 89 FB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_520deeb8 {
    meta:
        id = "5o9UC9JqTj7Dac5SwwtzD6"
        fingerprint = "v1_sha256_671c17835f30cce1e5d68dbf3a73d340069b1b55a2ac42fc132c008cb2da622e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { ED 48 89 44 24 30 44 89 6C 24 10 7E 47 48 89 C1 44 89 E8 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_77137320 {
    meta:
        id = "3kmfRJFJHWAGfblbavSHC0"
        fingerprint = "v1_sha256_ee48e0478845a61dbbdb5cc3ee5194eb272fcf6dcf139381f068c9af1557d0d4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 24 01 89 C7 31 F6 31 C9 48 89 A4 24 00 01 00 00 EB 1D 80 7A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a6a81f9c {
    meta:
        id = "21HkfwmIU64MTPG6zBij1a"
        fingerprint = "v1_sha256_0d31cc1f4a673c13e6c81c492acbe16e1e0dfb0b15913fb276ea4abff18b32af"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 57 00 54 43 50 00 47 52 45 00 4B 54 00 73 68 65 6C 6C 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_485c4b13 {
    meta:
        id = "4xenFmwa8OY2vNFRvW86i4"
        fingerprint = "v1_sha256_9625e4190559cc77f41ebef24f9bfa5e3d2e2259c12b301148c614b0f98b5835"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 7E 1F 8B 4C 24 4C 01 D1 0F B6 11 88 D0 2C 61 3C 19 77 05 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7146e518 {
    meta:
        id = "4RrQka9s7b85MoFrOOZJrB"
        fingerprint = "v1_sha256_374602254be1f5c1dbb00ad25d870722e03d674033dfcf953a2895e1f50c637d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 85 82 11 79 AF 20 C2 7A 9E 18 6C A9 00 21 E2 6A C6 D5 59 B4 E8 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6a77af0f {
    meta:
        id = "2JduIDWEgRo83aqNlHOrKW"
        fingerprint = "v1_sha256_7d7623dfc1e16c7c02294607ddf46edd12cdc7d39a2b920d8711dc47c383731b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 31 D1 89 0F 48 83 C7 04 85 F6 7E 3B 44 89 C8 45 89 D1 45 89 C2 41 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5f7b67b8 {
    meta:
        id = "36z4EarGGI1jSfOr19p0TB"
        fingerprint = "v1_sha256_b2aedc0361c1093d7a996f26d907da3e4654c32a6dbcdbab441c19d4207f2e2a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 38 83 CF FF 89 F8 5A 59 5F C3 57 56 83 EC 04 8B 7C 24 10 8B 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a3cedc45 {
    meta:
        id = "6Hw5VwiIzyFCfvwz8qvlck"
        fingerprint = "v1_sha256_9233e6faa43d8ea43ff3c71ecb5248d5d311b2a593825c299cac4466278cd020"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 2C 48 8B 03 48 83 E0 FE 48 29 C3 48 8B 43 08 48 83 E0 FE 4A 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7d05725e {
    meta:
        id = "5RIbQ7dsMfZ9TjH45bWbgD"
        fingerprint = "v1_sha256_ac2d0b81325ce7984bc09f93e61b42c8e312a31c75f09d37313d70cd40d3cf8b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 97 00 00 00 89 6C 24 08 89 74 24 04 89 14 24 0F B7 C0 89 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fa48b592 {
    meta:
        id = "1C8xJccbjHqFX4XwucmMB1"
        fingerprint = "v1_sha256_5648bcc96b1fdd1529b4b8765b1738594d0d61f7880b763e803cd89bd117e96b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c9e33befeec133720b3ba40bb3cd7f636aad80f72f324c5fe65ac7af271c49ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 31 C0 BA 01 00 00 00 B9 01 00 00 00 03 04 24 89 D7 31 D2 F7 F7 0F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b9a9d04b {
    meta:
        id = "2Y7ROlfQANydUFqnmjzPrl"
        fingerprint = "v1_sha256_61575576be4c1991bc381965a40e5d9d751bba2680a42907b0148651716419fc"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = "nexuszetaisacrackaddict"
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d2205527 {
    meta:
        id = "4wz07sYABnwzUKnqZc08ld"
        fingerprint = "v1_sha256_172ba256873cce61047a5198733cacaff4ef343c9cbd76f2fbbf0e1ed8003236"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "e4f584d1f75f0d7c98b325adc55025304d55907e8eb77b328c007600180d6f06"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CA B8 37 00 00 00 0F 05 48 3D 01 F0 FF FF 73 01 C3 48 C7 C1 C0 FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ab073861 {
    meta:
        id = "1tOxUEZj1tYwYvvzJcVbV2"
        fingerprint = "v1_sha256_251b92c4fec9d113025c6869c279247a3dd16ee094c8861fe43a33f87132bf75"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "175444a9c9ca78565de4b2eabe341f51b55e59dec00090574ee0f1875422cbac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { AC 00 00 00 54 60 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_637f2c04 {
    meta:
        id = "1oUiiK9vQBXCFQgLQQ5vnF"
        fingerprint = "v1_sha256_cff4aa6c613ccc64f64441f7e40f79d3a22b5c12856c32814545bd41d5f112bd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 48 8B 45 E0 0F B6 00 38 C2 0F 95 C0 48 FF 45 E8 48 FF 45 E0 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_aa39fb02 {
    meta:
        id = "66hiTFO8SXhb2H3loj7Qjz"
        fingerprint = "v1_sha256_ffa95d92a2b619008bd5918cd34a17cd034b2830dc09d495db4b0c397b1cb53a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 DE 8D 40 F1 3C 01 76 D7 80 FA 38 74 D2 80 FA 0A 74 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0bce98a2 {
    meta:
        id = "3CMKLB7rSHBzL1uhCJWNwz"
        fingerprint = "v1_sha256_04d10ef03c178fb101d3c6b6d3b36f0aa04149b9b35a33c3d10d17af1fc07625"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1b20df8df7f84ad29d81ccbe276f49a6488c2214077b13da858656c027531c80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4B 52 41 00 46 47 44 43 57 4E 56 00 48 57 43 4C 56 47 41 4A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3a56423b {
    meta:
        id = "5m0tPpxaxmciLCCBuzVX3d"
        fingerprint = "v1_sha256_0c2765a5c1b331eb9ff5e542bc72eff7be3506e6caef94128413d500086715c6"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 1C 8B 44 24 20 0F B6 D0 C1 E8 08 89 54 24 24 89 44 24 20 BA 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d18b3463 {
    meta:
        id = "6rEV5EkQCjrOfivy9aNdyk"
        fingerprint = "v1_sha256_f906c6f9baae6d6fa3f42e84607549bae44ed9ca847fd916d04f2671eef1caa1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "cd86534d709877ec737ceb016b2a5889d2e3562ffa45a278bc615838c2e9ebc3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { DF 77 95 8D 42 FA 3C 01 76 8E 80 FA 0B 74 89 80 FA 15 74 84 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fe721dc5 {
    meta:
        id = "1IgFaEHPMvTX1Vq7UJency"
        fingerprint = "v1_sha256_e9312eefb5f14a27d96e973139e45098c2f62a24d5254ca24dea64b9888a4448"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 18 EB E1 57 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_575f5bc8 {
    meta:
        id = "6kK21tDg8tUY3ZAJHpiQy2"
        fingerprint = "v1_sha256_dec143d096f5774f297ce90ef664ae50c40ae4f87843bbb34e496565c0faf3b2"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 5A 56 5B 5B 55 42 44 5E 59 52 44 44 00 5E 73 5E 45 52 54 43 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_449937aa {
    meta:
        id = "6aPq2MTjBgjphCLLn0bnlS"
        fingerprint = "v1_sha256_d459e46893115dbdef46bcaceb6a66255ef3a389f1bf7173b0e0bd0d8ce024fb"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "6f27766534445cffb097c7c52db1fca53b2210c1b10b75594f77c34dc8b994fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 5B 72 65 73 6F 6C 76 5D 20 46 6F 75 6E 64 20 49 50 20 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_2e3f67a9 {
    meta:
        id = "48II8cA1EYQVTbQmNLyCLM"
        fingerprint = "v1_sha256_8c83c5d32c58041444f33264f692a7580c76324d2cbad736fdd737bdfcd63595"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 53 83 EC 04 0F B6 74 24 14 8B 5C 24 18 8B 7C 24 20 0F B6 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_01e4a728 {
    meta:
        id = "7ZOekrVgY2Zj6X3qoTLKND"
        fingerprint = "v1_sha256_753936b97a36c774975a1d0988f6f908d4b5e5906498aa34c606d4cd971f1ba5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 44 24 23 48 8B 6C 24 28 83 F9 01 4A 8D 14 20 0F B6 02 88 45 08 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_64d5cde2 {
    meta:
        id = "5f3E7NBzRuaaDZGKF8r4xg"
        fingerprint = "v1_sha256_08f3635e5517185cae936b39f503bbeba5aed2e36abdd805170a259bc5e3644f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "caf2a8c199156db2f39dbb0a303db56040f615c4410e074ef56be2662752ca9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 35 7E B3 02 00 D0 02 00 00 07 01 00 00 0E 00 00 00 18 03 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0d73971c {
    meta:
        id = "WDnqtUcVMqrKB6IBjDeMF"
        fingerprint = "v1_sha256_56f3bac05fce0a0458e5b80197335e7bef6dcd50b9feb6f1008b8679f29cf37a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C2 83 EB 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 31 F0 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_82c361d4 {
    meta:
        id = "1RjOsjm3JjIkIhM7S65VKY"
        fingerprint = "v1_sha256_766a964d7d35525fbc88adcf86fb69d11f9c63c0d28ceefb3ae79797a7161193"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f8dbcf0fc52f0c717c8680cb5171a8c6c395f14fd40a2af75efc9ba5684a5b49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 23 CB 67 4C 94 11 6E 75 EC A6 76 98 23 CC 80 CF AE 3E A6 0C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ec591e81 {
    meta:
        id = "47cfeIi0Ex7a91bNsr1Am0"
        fingerprint = "v1_sha256_f2a147fe7f98d2b3141a1fda118ee803c81d9bc6f498bfaf3557665397eb44da"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7d45a4a128c25f317020b5d042ab893e9875b6ff0ef17482b984f5b3fe87e451"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 22 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0eba3f5a {
    meta:
        id = "6q6VQoVgd2zOA72cp1PqMq"
        fingerprint = "v1_sha256_bcb2f1e1659102f39977fac43b119c58d6c72f828c3065e2318f671146e911da"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 89 F0 66 89 45 C4 C7 45 DC 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e43a8744 {
    meta:
        id = "3Yw6YkDkjiQjU6l529RzMt"
        fingerprint = "v1_sha256_17c52d2b720fa2e98c3e9bb077525a695a6e547a66e8c44fcc1e26e48df81adf"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 23 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6e8e9257 {
    meta:
        id = "20cmUuDwEbsFVCkA4w1bH1"
        fingerprint = "v1_sha256_67973257e578783838f18dc8ae994f221ad1c1b3f4a04a2b6b523da5ebd8c95b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 53 83 EC 04 8B 5C 24 18 8B 7C 24 20 8A 44 24 14 8A 54 24 1C 88 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ac253e4f {
    meta:
        id = "6PdXilf2ufwXpoAjJ3FJy2"
        fingerprint = "v1_sha256_1ab463fce01148c2cc95659fdf8b05e597d9b4eeabe81a9cdfa1da3632d72291"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 31 C9 EB 0A 6B C1 0A 0F BE D2 8D 4C 02 D0 8A 17 48 FF C7 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_994535c4 {
    meta:
        id = "4HJAUV7L0x22DKxT6B6Qc6"
        fingerprint = "v1_sha256_c83c8c9cdfea1bf322115e5b23d751b226a5dbf42fc41faac172d36192ccf31f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "376a2771a2a973628e22379b3dbb9a8015c828505bbe18a0c027b5d513c9e90d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 74 07 31 C0 48 FF C3 EB EA FF C0 83 F8 08 75 F4 48 8D 73 03 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a68e498c {
    meta:
        id = "4idkpksJWqSUElLup7ECsN"
        fingerprint = "v1_sha256_e4552813dc92b397c5ba78f32ee6507520f337b55779a3fc705de7e961f8eb8f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 39 D0 7E 25 8B 4C 24 38 01 D1 8A 11 8D 42 9F 3C 19 77 05 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_88de437f {
    meta:
        id = "5WThKsuuAbSU2DDItDXttt"
        fingerprint = "v1_sha256_233dbf3d13c35f4c9c7078d67ea60086355c801ce6515f9d3c518e95afd39d85"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 08 8B 4C 24 04 85 D2 74 0D 31 C0 89 F6 C6 04 08 00 40 39 D0 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_95e0056c {
    meta:
        id = "5w66i3cpUHUUjiyYAkiKUh"
        fingerprint = "v1_sha256_9e34891d28034d1f4fc3da5cb99df8fc74f0b876903088f5eab5fe36e0e0e603"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "45f67d4c18abc1bad9a9cc6305983abf3234cd955d2177f1a72c146ced50a380"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 50 46 00 13 10 11 16 17 00 57 51 47 50 00 52 43 51 51 00 43 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b548632d {
    meta:
        id = "wNp9K1AJ80k2tEdQee662"
        fingerprint = "v1_sha256_bfb46457f8b79548726e3988d649f94e04f26f9e546aae70ece94defae6bab8a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "639d9d6da22e84fb6b6fc676a1c4cfd74a8ed546ce8661500ab2ef971242df07"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 0B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e0cf29e2 {
    meta:
        id = "4NYEFVqpzinwYtmD4dmQBo"
        fingerprint = "v1_sha256_693e27da8cbab32954cc2c9ba648151ad9fc21fe53251628145d7b436ec5e976"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C2 83 FE 01 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1754b331 {
    meta:
        id = "4mv34G4zBSn2niETemOnSj"
        fingerprint = "v1_sha256_fde04b0e31a00326f9d011198995999ff9b15628f5ff4139ec7dec19ac0c59c9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "0d89fc59d0de2584af0e4614a1561d1d343faa766edfef27d1ea96790ac7014b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CF 07 66 5F 10 F0 EB 0C 42 0B 2F 0B 0B 43 C1 42 E4 C2 7C 85 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3278f1b8 {
    meta:
        id = "7EA8qWJzSen7pYdKqk3JRh"
        fingerprint = "v1_sha256_4d709e8e2062099ac06b241408e52bcb86bbf8163faaffbcff68a05f864e1b3f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D2 0F B6 C3 C1 E0 10 0F B6 C9 C1 E2 18 09 C2 0F B6 44 24 40 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ab804bb7 {
    meta:
        id = "1D16ruOB74MUR8DqnM59hO"
        fingerprint = "v1_sha256_cef2ffafe152332502fb0d72d014c81b90dc9ad4f4491f1b2f2f9c1f73cc7958"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8f0cc764729498b4cb9c5446f1a84cde54e828e913dc78faf537004a7df21b20"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4A 75 05 0F BE 11 01 D0 89 C2 0F B7 C0 C1 FA 10 01 C2 89 D0 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_dca3b9b4 {
    meta:
        id = "45eeGIZrI9i9rLlnHYuuns"
        fingerprint = "v1_sha256_f85dfc1c00706d7ac11ef35c41c471383ef8b019a5c2566b27072a5ef5ad5c93"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "a839437deba6d30e7a22104561e38f60776729199a96a71da3a88a7c7990246a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 45 F4 01 8B 45 F4 3B 45 F0 75 11 48 8B 45 F8 48 2B 45 D8 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ae9d0fa6 {
    meta:
        id = "3l2TC3GjCwi1AxgIqTGPwA"
        fingerprint = "v1_sha256_8da5b14b95d96de5ced8bcab98e23973e449c1b5ca101f39a2114bb8e74fd9a5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 EC 04 8A 44 24 18 8B 5C 24 14 88 44 24 03 8A 44 24 10 25 FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_612b407c {
    meta:
        id = "5AHCd1zQvGIgS0kIFt1ic"
        fingerprint = "v1_sha256_6514725a32f7c28be7de5ff6fe1363df7c50e2cd6c8c79824ec4cbeadda2ca31"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7833bc89778461a9f46cc47a78c67dda48b498ee40b09a80a21e67cb70c6add1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 11 B2 73 45 2B 7A 57 E2 F9 77 A2 23 EC 7C 0C 29 FE 3F B2 DE 28 6C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5da717f {
    meta:
        id = "6sBi4MnjD32Be4prXyWkKl"
        fingerprint = "v1_sha256_034dae5bea7536e8c8aa22b8b891b9c991b94f04be12c9fe6d78ddf07a2365d9"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 66 83 7C 24 34 FF 66 89 46 2C 0F 85 C2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d33095d4 {
    meta:
        id = "7FRKpjmesAniaepHiL3TIj"
        fingerprint = "v1_sha256_b7feaec65d72907d08c98b09fb4ac494ceee7d7bd51c09063363c617e3f057a4"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "72326a3a9160e9481dd6fc87159f7ebf8a358f52bf0c17fbc3df80217d032635"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 66 83 7C 24 54 FF 66 89 46 04 0F 85 CB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_4e2246fb {
    meta:
        id = "2e2cZUxlTHdCZzCg4mGpFx"
        fingerprint = "v1_sha256_6d2e1300286751a5e1ae683e9aab2f59bfbb20d1cc18dcce89c06ecadf25a3e6"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 B8 01 00 00 00 31 DB CD 80 EB FA 8D 8B 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5981806 {
    meta:
        id = "2ZRyYsOpBgi7vU6v8CRmLE"
        fingerprint = "v1_sha256_e625323543aa5c8374a179dfa51c3f5be1446459c45fa7c7a27ae383cf0f551b"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "784f2005853b5375efaf3995208e4611b81b8c52f67b6dc139fd9fec7b49d9dc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 3F 00 00 66 83 7C 24 38 FF 66 89 46 04 0F 85 EA }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c6055dc9 {
    meta:
        id = "4DsrFkgGy7e9VrGyT4WcYR"
        fingerprint = "v1_sha256_4d9d7c44f0d3ae60275720ae5faf3c25c368aa6e7d9ab5ed706a30f9a7ffd3b8"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c1718d7fdeef886caa33951e75cbd9139467fa1724605fdf76c8cdb1ec20e024"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 7F 43 80 77 39 CF 7E 09 83 C8 FF 5A 5D 8A 0E }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3b9675fd {
    meta:
        id = "2hICsT2dTAuEDxOj2U0o9K"
        fingerprint = "v1_sha256_61ff7cb8d664291de5cf0c82b80cf0f4001c41d3f02b7f4762f67eb8128df15d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4ec4bc88156bd51451fdaf0550c21c799c6adacbfc654c8ec634ebca3383bd66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 78 10 85 C9 75 65 48 8B 8C 24 A0 00 00 00 48 89 48 10 0F B6 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1c0d246d {
    meta:
        id = "1qfqvKCHNAh1qlJLNoqf0x"
        fingerprint = "v1_sha256_7a101e6d2265e09eb6c8d0f1a2fe54c9aa353dfd8bd156926937f4aec86c3ef1"
        version = "1.0"
        date = "2021-04-13"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Based off community provided sample"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "211cfe9d158c8a6840a53f2d1db2bf94ae689946fffb791eed3acceef7f0e3dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E7 C0 00 51 78 0F 1B FF 8A 7C 18 27 83 2F 85 2E CB 14 50 2E }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ad337d2f {
    meta:
        id = "5x19hyeaqRCFtqIWBBbO3A"
        fingerprint = "v1_sha256_dba630c1deb00b0dbd9f895a9b93393bc634150c8f32527b02d8dd71dc806e7d"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "012b717909a8b251ec1e0c284b3c795865a32a1f4b79706d2254a4eb289c30a7"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 75 14 80 78 FF 2F 48 8D 40 FF 0F 94 C2 48 39 D8 77 EB 84 D2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_88a1b067 {
    meta:
        id = "6IhHrPavJY3molXJ3Lnudq"
        fingerprint = "v1_sha256_0755f1f974734ccd4ecc444217bf52ed306d1dc32c05841ba9ca6d259e1a147e"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "1a62db02343edda916cbbf463d8e07ec2ad4509fd0f15a5f6946d0ec6c332dd9"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 55 89 E5 0F B6 55 08 0F B6 45 0C C1 E2 18 C1 E0 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_76bbc4ca {
    meta:
        id = "6TXzm6cdOIoI1yq4Agg7zV"
        fingerprint = "v1_sha256_855b7938b92b5645fcefd2ec1e2ccb71269654816f362282ccbf9aef1c01c8a0"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "1a9ff86a66d417678c387102932a71fd879972173901c04f3462de0e519c3b51"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 40 2D E9 00 40 A0 E1 28 20 84 E2 0C 00 92 E8 3B F1 FF EB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0bfc17bd {
    meta:
        id = "15fEzRC7nrX8qh0BBJirHc"
        fingerprint = "v1_sha256_ef83bc9ae3c881d09b691db42a1712b500a5bb8df34060a6786cfdc6caaf5530"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1cdd94f2a1cb2b93134646c171d947e325a498f7a13db021e88c05a4cbb68903"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 24 64 0F CD 48 8D 14 52 41 0F B6 4C D7 14 D3 E8 01 C5 83 7C 24 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_389ee3e9 {
    meta:
        id = "2CuVvgbXuOOMBaMV00q2v6"
        fingerprint = "v1_sha256_fedeae98d468a11c3eaa561b9d5433ec206bdd4caed5aed7926434730f7f866b"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 45 00 EB 2C 8B 4B 04 8B 13 8B 7B 18 8B 01 01 02 8B 02 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_cc93863b {
    meta:
        id = "5VFdIxR9D72dmrE8V4Fovw"
        fingerprint = "v1_sha256_881998dee010270d7cefae5b59a888e541d4a2b93e3e52ae0abe0df41371c50d"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C3 57 8B 44 24 0C 8B 4C 24 10 8B 7C 24 08 F3 AA 8B 44 24 08 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_8aa7b5d3 {
    meta:
        id = "4logH3Axge1iRSNBujvw0I"
        fingerprint = "v1_sha256_3c99b7b126184b75802c7198c81f4783af776920edc6e964dbe726d28d88f64d"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 4C 24 14 8B 74 24 0C 8B 5C 24 10 85 C9 74 0D 31 D2 8A 04 1A 88 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_76908c99 {
    meta:
        id = "47mBhQ0KB2pIGixCQoI2FU"
        fingerprint = "v1_sha256_bd8254e888b1ea93ca9aad92ea2c8ece1f2d03ae2949ca4c3743b6e339ee21e0"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "533a90959bfb337fd7532fb844501fd568f5f4a49998d5d479daf5dfbd01abb2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 64 24 F8 48 89 04 24 48 8B C6 48 8B 34 24 48 87 CF 48 8B 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1538ce1a {
    meta:
        id = "Fx1DzdesduqVP9aTXSGOh"
        fingerprint = "v1_sha256_cf2dd11da520640c6a64e05c4679072a714d8cf93d5f5aa3a1eca8eb3e9c8b3b"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FD 00 00 00 FD 34 FD FD 04 40 FD 04 FD FD 7E 14 FD 78 14 1F 0F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_07b1f4f6 {
    meta:
        id = "2N8fnN815PxeAT3Yqr8eOM"
        fingerprint = "v1_sha256_4af1a20e29e0c9b62e1530031e49a3d7b37d4e9a547d89a270a2e59e0c7852cc"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FD 08 FD 5C 24 48 66 FD 07 66 FD 44 24 2E 66 FD FD 08 66 FD 47 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_feaa98ff {
    meta:
        id = "3ulwCOUI2aKq7koWFRMOp2"
        fingerprint = "v1_sha256_06be9d8bcfcb7e6b600103cf29fa8a94a457ff56e8c7018336c270978a57ccbf"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F FD FD FD FD FD FD 7A 03 41 74 5E 42 31 FD FD 6E FD FD FD FD }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3acd6ed4 {
    meta:
        id = "7DYu2pVrZxYckvJuVgZvFJ"
        fingerprint = "v1_sha256_ab284d41af8e1920fa54ac8bfab84bac493adf816aebce60490ab22c0e502201"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2644447de8befa1b4fe39b2117d49754718a2f230d6d5f977166386aa88e7b84"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E5 7E 44 4C 89 E3 31 FF 48 C1 E3 05 48 03 5D 38 48 89 2B 44 88 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_eb940856 {
    meta:
        id = "6Sxf737hoBA7DeaQIeRpKT"
        fingerprint = "v1_sha256_d7bb2373a35ea97a11513e80e9a561f53a8f0b9345f392e8e7f042d4cb2d7d20"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fbf814c04234fc95b6a288b62fb9513d6bbad2e601b96db14bb65ab153e65fef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 84 24 80 00 00 00 31 C9 EB 23 48 89 4C 24 38 48 8D 84 24 C8 00 }
    condition:
        all of them
}

