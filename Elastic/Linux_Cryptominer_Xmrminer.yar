rule Linux_Cryptominer_Xmrminer_70c153b5 {
    meta:
        id = "3EpXbdGlpd5ZwSeXTnjPUP"
        fingerprint = "v1_sha256_e2fc0721435c656a16e59b6747563df17f0f54a4620efc403a3bba717ccb0f38"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "55b133ba805bb691dc27a5d16d3473650360c988e48af8adc017377eed07935b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EC 18 BA 08 00 00 00 48 8D 4C 24 08 48 89 74 24 08 BE 02 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_98b00f9c {
    meta:
        id = "3eEMt2qh65FZee7trSM3Tf"
        fingerprint = "v1_sha256_cf8c5deddf22e7699cd880bd3f9f28721db5ece6705be4f932e1d041893eef71"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "c01b88c5d3df7ce828e567bd8d639b135c48106e388cd81497fcbd5dcf30f332"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 38 DC DF 49 89 D4 66 0F 7F 24 1A 66 0F EF C3 66 42 0F 7F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_2b250178 {
    meta:
        id = "3QPkbHDawTyBLr16PTrhQf"
        fingerprint = "v1_sha256_067705c52de710372b4a2a3b77427106068ad2d9a8e56602e315d09e7b8b6206"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "636605cf63d3e335fe9481d4d110c43572e9ab365edfa2b6d16d96b52d6283ef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 03 7E 11 8B 44 24 38 89 EF 31 D2 89 06 8B 44 24 3C 89 46 04 F7 C7 02 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_67bf4b54 {
    meta:
        id = "6qRUoWeDunaCsd073RLVBW"
        fingerprint = "v1_sha256_448f5b9dc3c17984464c15f6d542f495a52b0531acc362dedfe3d1a20b932969"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "9d33fba4fda6831d22afc72bf3d6d5349c5393abb3823dfa2a5c9e391d2b9ddf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 46 70 4A 8B 2C E0 83 7D 00 03 74 DA 8B 4D 68 85 C9 74 DC 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_504b42ca {
    meta:
        id = "xL04wpvGRGtgGZU8BJ5RF"
        fingerprint = "v1_sha256_dd3ed5350e0229ac714178a30de28893c30708734faec329c776e189493cf930"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D7 8B 04 8C 44 8D 50 FF 4C 89 04 C6 44 89 14 8C 75 D7 48 8B 2E 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d1bb752f {
    meta:
        id = "6QlXRrlfTtNFciJZFHgmv7"
        fingerprint = "v1_sha256_47aa5516350d5c00d1387649df46ce8f09d87bdfafeaa4cbf1c3ef5f2e0b9023"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 12 48 29 C8 48 2B 83 B0 00 00 00 48 C1 E8 03 48 F7 E2 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d625fcd2 {
    meta:
        id = "otYqIxV6arBOx0ELVT7Dp"
        fingerprint = "v1_sha256_b95b66392e1a07e0b6acd718a9501cede76e57561e69701e9e881bd3fbd3fe39"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 00 00 40 00 0C C0 5C 02 60 01 02 03 12 00 40 04 50 09 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_02d19c01 {
    meta:
        id = "1ddHfFCs1BWEXKIlKu0zir"
        fingerprint = "v1_sha256_43a1dc49bf75cd13637c37290d47b4d6fc1b2c2ac252b64725c0c64e1dd745c6"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "b6df662f5f7566851b95884c0058e7476e49aeb7a96d2aa203393d88e584972f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4C 8D 7E 15 41 56 41 55 41 54 41 BB 03 00 00 00 55 53 48 89 FB 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_2dd045fc {
    meta:
        id = "2VSnNGGSd3LskHZYecGDPa"
        fingerprint = "v1_sha256_fa23ca75027f7a5e73652173c9e84112a0b5cd3008fc453fdb33c980dc7b7b24"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "30a77ab582f0558829a78960929f657a7c3c03c2cf89cd5a0f6934b79a74b7a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { BA 0E 00 00 00 74 25 48 8B 8C 24 B8 00 00 00 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d1a814b0 {
    meta:
        id = "2Hxz7EqseaE1iMn02gE1Jn"
        fingerprint = "v1_sha256_a06f5d5be87153be1253c2e20a60fa36701a745813926be03ee466ce8e2285b0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 48 8B 44 24 58 49 89 41 08 8B 01 48 C1 E0 05 4D 8D 04 07 48 8B 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_c6218e30 {
    meta:
        id = "2vyxCDwXVtXB2NHoxX2I4Z"
        fingerprint = "v1_sha256_3efbc3cb1591a9340df10640b411a9ab4c41e0aa26c1677d9def8b82e4c246f4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "b43ddd8e355b0c538c123c43832e7c8c557e4aee9e914baaed0866ee5d68ee55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { AC 24 B0 00 00 00 48 89 FA 66 0F EF DD 48 C1 E2 20 66 41 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_b17a7888 {
    meta:
        id = "2uLuNHvGN25GgCHxnCbMDU"
        fingerprint = "v1_sha256_a7f6daa5c42d186d2c5a027fdb35b45287c3564a7b57b8a2f53659e6ca90602a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "65c9fdd7c559554af06cd394dcebece1bc0fdc7dd861929a35c74547376324a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D4 FF C5 55 F4 C9 C5 F5 D4 CD C4 41 35 D4 C9 C5 B5 D4 C9 C5 C5 }
    condition:
        all of them
}

