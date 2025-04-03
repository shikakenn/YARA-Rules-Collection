rule Linux_Trojan_Gafgyt_83715433 {
    meta:
        id = "4EfCt8wOhBcZRTUV6YT0ZO"
        fingerprint = "v1_sha256_7a7328322c2c1e128e267e92de0964e78ad9f49b7de8ec69d7f0632c69723a7d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "3648a407224634d76e82eceec84250a7506720a7f43a6ccf5873f478408fedba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 45 08 88 10 FF 45 08 8B 45 08 0F B6 00 84 C0 75 DB C9 C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_28a2fe0c {
    meta:
        id = "2MCKdFvU3DlsX2O9S675Qx"
        fingerprint = "v1_sha256_04bbc6c40cdd71b4185222a822d18b96ec8427006221f213a1c9e4d9c689ce5c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 2F 78 33 38 2F 78 46 4A 2F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_eb96cc26 {
    meta:
        id = "1ltF2rtOx6TWapbYJAc1hT"
        fingerprint = "v1_sha256_3d8740a6cca4856a73ea745877a3eb39cbf3ad4ca612daabd197f551116efa04"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "440318179ba2419cfa34ea199b49ee6bdecd076883d26329bbca6dca9d39c500"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 49 6E 66 6F 3A 20 0A 00 5E 6A 02 5F 6A 01 58 0F 05 6A 7F 5F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_5008aee6 {
    meta:
        id = "5QgMArRW9qPevmwDkNhYRW"
        fingerprint = "v1_sha256_538bae17dcf0298e379f656e1dba794b75af6c7448a23253a51994bde9d30524"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b32cd71fcfda0a2fcddad49d8c5ba8d4d68867b2ff2cb3b49d1a0e358346620c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 50 16 B4 87 58 83 00 21 84 51 FD 13 4E 79 28 57 C3 8B 30 55 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6321b565 {
    meta:
        id = "2cla5BXLtMFNWMT8GGOsNO"
        fingerprint = "v1_sha256_ad5c73ab68059101acf2fd8cfb3d676fd1ff58811e1c4b9008c291361ee951b8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "cd48addd392e7912ab15a5464c710055f696990fab564f29f13121e7a5e93730"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D8 89 D0 01 C0 01 D0 C1 E0 03 8B 04 08 83 E0 1F 0F AB 84 9D 58 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a6a2adb9 {
    meta:
        id = "1PVkPAcQJ15nXIQ5gcO4xd"
        fingerprint = "v1_sha256_8f5fc4cb1ad51178701509a44a793e119fe7e7fad97eafcac8be14fce64e3b7b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { CC 01 C2 89 55 B4 8B 45 B4 C9 C3 55 48 89 E5 48 81 EC 90 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_c573932b {
    meta:
        id = "6Jls5sfaaffWrhiwX597UM"
        fingerprint = "v1_sha256_174a3fcebc1e17cc35ddc11fde1798164b5783fc51fdf16581a9690c3b4d6549"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 7D 18 00 74 22 8B 45 1C 83 E0 02 85 C0 74 18 83 EC 08 6A 2D FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a10161ce {
    meta:
        id = "1mIQgqFmuqudZznn3lp2jB"
        fingerprint = "v1_sha256_12ba13a746300d1ab1d0386b86ec224eebf4e6d0b3688495c2fee6a7eccc361d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 B0 8B 45 BC 48 63 D0 48 89 D0 48 C1 E0 02 48 8D 14 10 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ae01d978 {
    meta:
        id = "sjpDj3tLG17xLgUoY4diQ"
        fingerprint = "v1_sha256_c6c22b11dc1f0d4996e5da92c6edf58b7d21d7be40da87ddd39ed0e2d4c84072"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 2C 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9e9530a7 {
    meta:
        id = "47SlZvfWvFgeranunWkF1c"
        fingerprint = "v1_sha256_6a5a80e58c86a80f8954e678a2cc26b258d7d7c50047a3e71f3580f1780e3454"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F6 48 63 FF B8 36 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_5bf62ce4 {
    meta:
        id = "1hK9lkwbz5G4xKmBZR0zDe"
        fingerprint = "v1_sha256_848e0c796584cfa21afc182da5f417f5467ae84c74f52cabc13e0f5de4990232"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E5 56 53 31 F6 8D 45 10 83 EC 10 89 45 F4 8B 55 F4 46 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f3d83a74 {
    meta:
        id = "1ljHOqrcdtAwbBrwSYxEPc"
        fingerprint = "v1_sha256_2db46180e66c9268a97d63cd1c4eb8439e6882b4e3277bc4848e940e4d25482f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { DC 00 74 1B 83 7D E0 0A 75 15 83 7D E4 00 79 0F C7 45 C8 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_807911a2 {
    meta:
        id = "6VX1n8vhOSLOWEcbMDqI55"
        fingerprint = "v1_sha256_66b15304d5ed22daea666bd0e2b18726b8a058361ff8d69b974bfded933a4d8c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FE 48 39 F3 0F 94 C2 48 83 F9 FF 0F 94 C0 84 D0 74 16 4B 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9c18716c {
    meta:
        id = "pmKFCzVe3slThz97O9g2t"
        fingerprint = "v1_sha256_0e70dc82b2049a6f5efcc501e18e6f87e04a2d50efcb5143240c68c4a924de52"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FC 80 F6 FE 59 21 EC 75 10 26 CF DC 7B 5A 5B 4D 24 C9 C0 F3 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fbed4652 {
    meta:
        id = "26ygVKl3N9PE0yfAhKJw7v"
        fingerprint = "v1_sha256_fc1f501123ab7421034e183186b077f65838b475f883d4ff04e8fc8a283424ef"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "2ea21358205612f5dc0d5f417c498b236c070509531621650b8c215c98c49467"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 02 00 00 2B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_94a44aa5 {
    meta:
        id = "odYbBmZuKg3nPgdX9ccZw"
        fingerprint = "v1_sha256_deb46c2960dc4868b7bac1255d8753895950bc066dec03674a714860ff72ef2c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "a7694202f9c32a9d73a571a30a9e4a431d5dfd7032a500084756ba9a48055dba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 83 F8 FF 0F 45 C2 48 8B 4C 24 08 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e0673a90 {
    meta:
        id = "5jnu9tvX3yT4Xejxot0Bfe"
        fingerprint = "v1_sha256_149147eedd66f9ca2dad9cb69f37abc849d44331ec1b5d2917ab3867ced0b274"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 E8 0F B6 00 84 C0 74 17 48 8B 75 E8 48 FF C6 48 8B 7D F0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_821173df {
    meta:
        id = "2c2YDo3dCureYpSXug1XsL"
        fingerprint = "v1_sha256_1c6c7666983c43176aa1a9628fb4352f8f11729e02dda13669ca2e62aed5f4ee"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "de7d1aff222c7d474e1a42b2368885ef16317e8da1ca3a63009bf06376026163"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D0 48 FF C8 48 03 45 F8 48 FF C8 C6 00 00 48 8B 45 F8 48 C7 C1 FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_31796a40 {
    meta:
        id = "5va4a72wrcynGCUxEBDgIG"
        fingerprint = "v1_sha256_0e0e901d12edd77e77a205f8547f891f483fc8676493e9b7a324e970225af3c9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "227c7f13f7bdadf6a14cc85e8d2106b9d69ab80abe6fc0056af5edef3621d4fb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 14 48 63 D0 48 8D 45 C0 48 8D 70 04 48 8B 45 E8 48 8B 40 18 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_750fe002 {
    meta:
        id = "1QbI7w4YLgTVqYwzDtjejx"
        fingerprint = "v1_sha256_eb9907d8a63822c2e3ab57d43dca8ede7876610f029e2f9c10c9eeace9ea0078"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 8B 45 0C 40 8A 00 3C FC 75 06 C6 45 FF FE EB 50 8B 45 0C 40 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6122acdf {
    meta:
        id = "WkSFatRfyzhq7Z8jvlnen"
        fingerprint = "v1_sha256_140b32a8f2b7493b068e63a05b3d9baec6ec14c9f2062c7e760dde96335e29f1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 B0 00 FC 8B 7D E8 F2 AE 89 C8 F7 D0 48 48 89 45 F8 EB 03 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a0a4de11 {
    meta:
        id = "6di1vX3KrXN8LC2g1KwMFE"
        fingerprint = "v1_sha256_220c6ba82b906f070123b3bae9aafa72c0fb3bc8d5858a4f4bd65567076eb73d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 42 0D 83 C8 10 88 42 0D 48 8B 55 D8 0F B6 42 0D 83 C8 08 88 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a473dcb6 {
    meta:
        id = "1wEeGpKk96hCLzYGh2Xbv3"
        fingerprint = "v1_sha256_106ee9cd9c368674ae08b835f54dbb6918b553e3097aae9b0de88f55420f046b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "7ba74e3cb0d633de0e8dbe6cfc49d4fc77dd0c02a5f1867cc4a1f1d575def97d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 49 56 04 0B 1E 46 1E B0 EB 10 18 38 38 D7 80 4D 2D 03 29 62 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_30444846 {
    meta:
        id = "5wfWxkumTyyi8H3ZZsighY"
        fingerprint = "v1_sha256_26bc95efb2ea69fece52cf3ab38ce35891c77fc0dac3e26e5580ba3a88e112e9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c84b81d79d437bb9b8a6bad3646aef646f2a8e1f1554501139648d2f9de561da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 64 20 2B 78 20 74 66 74 70 31 2E 73 68 3B 20 73 68 20 74 66 74 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ea92cca8 {
    meta:
        id = "138Qv1X9yUsFc1opZz4CqL"
        fingerprint = "v1_sha256_5a9598b3fd37b15444063403a481df1a43894ddcbbd343961e1c770cb74180c9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 53 65 6C 66 20 52 65 70 20 46 75 63 6B 69 6E 67 20 4E 65 54 69 53 20 61 6E 64 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d4227dbf {
    meta:
        id = "1H8LypuG4PbTTlhirzBlQv"
        fingerprint = "v1_sha256_7953b8d08834315a6ca2c0c8ac1ec7b74a6ffcb71cec4fc053c24e1b59232c0c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 54 24 30 C7 04 24 18 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_09c3070e {
    meta:
        id = "3zGuYyys3xToPBXlRpqaZT"
        fingerprint = "v1_sha256_f8f8e8883cf1e51fbaef81b8334ac5fa45a54682d285282da62c80e4aa50a48d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 C1 E8 06 48 89 C6 48 8B 94 C5 50 FF FF FF 8B 8D 2C FF FF FF 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fa19b8fc {
    meta:
        id = "lKvnmBDuZwXEoFG2LxxLJ"
        fingerprint = "v1_sha256_cddf3b9948b9bc685ff7d4c00377d0f80861169707777022297e549bd166dbf0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "a7cfc16ec33ec633cbdcbff3c4cefeed84d7cbe9ca1f4e2a3b3e43d39291cd6b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 02 63 10 01 0F 4B 85 14 36 B0 60 53 03 4F 0D B2 05 76 02 B7 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_eaa9a668 {
    meta:
        id = "2MTYYUfJpWHm6OX7g2hAQM"
        fingerprint = "v1_sha256_05e9047342a9d081a09f8514f0ec32d72bc43a286035014ada90b0243f92cfa8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 C0 0F B6 00 3C 2F 76 0B 48 8B 45 C0 0F B6 00 3C 39 76 C7 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_46eec778 {
    meta:
        id = "5MmHfFe3ViCeDPVjnpQJcZ"
        fingerprint = "v1_sha256_08e77a31005e14a06197857301e22d20334c1f2ef7fc06a4208643438377f4c4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 01 45 F8 48 83 45 E8 02 83 6D C8 02 83 7D C8 01 7F E4 83 7D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f51c5ac3 {
    meta:
        id = "2oubdgqzJ53eLJXjn39hCS"
        fingerprint = "v1_sha256_e82b5ddb760d5bdcd146e1de12ec34c4764e668543420765146e22dee6f5732b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 2A 8B 45 0C 0F B6 00 84 C0 74 17 8B 45 0C 40 89 44 24 04 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_71e487ea {
    meta:
        id = "3rHKGmTuRC8Uf7raxyRjLc"
        fingerprint = "v1_sha256_3de9e0e3334e9e6e5906886f95ff8ce3596f85772dc25021fb0ee148281cf81c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b8d044f2de21d20c7e4b43a2baf5d8cdb97fba95c3b99816848c0f214515295b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E0 8B 45 D8 8B 04 D0 8D 50 01 83 EC 0C 8D 85 40 FF FF FF 50 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6620ec67 {
    meta:
        id = "2YEteSlp6EMoSTulsWleXg"
        fingerprint = "v1_sha256_2df2c8cdc2cb545f916159d44a800708b55a2993cd54a4dcf920a6a8dc6361e7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b91eb196605c155c98f824abf8afe122f113d1fed254074117652f93d0c9d6b2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { AF 93 64 1A D8 0B 48 93 64 0B 48 A3 64 11 D1 0B 41 05 E4 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d996d335 {
    meta:
        id = "6ONQxUfLIM04XMDNo4qwJh"
        fingerprint = "v1_sha256_212c75ab61eac8b3ed2049966628dfc81ae5a620b4a4b38aaa0696d594910dea"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b511eacd4b44744c8cf82d1b4a9bc6f1022fe6be7c5d17356b171f727ddc6eda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D0 EB 0F 40 38 37 75 04 48 89 F8 C3 49 FF C8 48 FF C7 4D 85 C0 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d0c57a2e {
    meta:
        id = "697e4Wq8dm3CHQMbg1ieCc"
        fingerprint = "v1_sha256_2ac51f0943d573fdc9a39837aeefd9158c27a4b3f35fbbb0a058a88392a53c14"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_751acb94 {
    meta:
        id = "5ffmMCs3NJhVqjsneVpMNc"
        fingerprint = "v1_sha256_1963351d209168f4ae2268d245cfd5320e4442d00746d021088ffae98e5da454"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 54 6F 20 43 6F 6E 6E 65 63 74 21 20 00 53 75 63 63 65 73 66 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_656bf077 {
    meta:
        id = "3N77qlnNjDKpRNZJ2rQUE2"
        fingerprint = "v1_sha256_0c9728304e720eb2cd00afad8d16f309514473dece48fa94af6a72ca41705a36"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 28 48 8B 45 E8 0F B6 00 84 C0 74 14 48 8B 75 E8 48 FF C6 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e6d75e6f {
    meta:
        id = "7bSembN5g8J7r8uFJkUum3"
        fingerprint = "v1_sha256_339dd33a3313a4a94d2515cd4c2100ac6b9d5e0029881494c28dc3e7c8a05798"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "48b15093f33c18778724c48c34199a420be4beb0d794e36034097806e1521eb8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 CD 80 C3 8B 54 24 04 8B 4C 24 08 87 D3 B8 5B 00 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_7167d08f {
    meta:
        id = "2e8XV0ou40VAOzvMm57Gtb"
        fingerprint = "v1_sha256_88c07bf06801192f38ef66229a0aa5c1ef6242caeb080ce1c7cd13ad0d540c82"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0C 8A 00 3C 2D 75 13 FF 45 0C C7 45 E4 01 00 00 00 EB 07 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_27de1106 {
    meta:
        id = "Fc5iE14dBbp0uvhhZKysW"
        fingerprint = "v1_sha256_4e266e1ae31d7d86866b112a04ca38c0a8185c18ebb10ac6497bbaa69f51b2fd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0C 0F B6 00 84 C0 74 18 8B 45 0C 40 8B 55 08 42 89 44 24 04 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_148b91a2 {
    meta:
        id = "3lxWEaiJqfYrl1UQMQG8Sx"
        fingerprint = "v1_sha256_1a974c0882c2d088c978a52e5b535807c86f117cf2f05c40c084e849b1849f5b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "d5b2bde0749ff482dc2389971e2ac76c4b1e7b887208a538d5555f0fe6984825"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C6 45 DB FC EB 04 C6 45 DB FE 0F B6 45 DB 88 45 FF 48 8D 75 FF 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_20f5e74f {
    meta:
        id = "27VdwKlx97VZJRNQ9Jk5aW"
        fingerprint = "v1_sha256_067f1c15961c1ddceecb490b338db9f5b8501d89b38e870edfa628d21527dc1c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9084b00f9bb71524987dc000fb2bc6f38e722e2be2832589ca4bb1671e852f5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D8 8B 45 D0 8B 04 D0 8D 50 01 83 EC 0C 8D 85 38 FF FF FF 50 8D 85 40 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_1b2e2a3a {
    meta:
        id = "3RGtJbiUTiBfoXqZcQ3gGy"
        fingerprint = "v1_sha256_6f40f868d20f0125721eb2a7934b356d69b695d4a558155a2ddcd0107d3f8c30"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 7D 18 00 74 25 8B 45 1C 83 E0 02 85 C0 74 1B C7 44 24 04 2D 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_620087b9 {
    meta:
        id = "1ZvstDRhl37CAhWSen0N87"
        fingerprint = "v1_sha256_411451ea326498a25af8be5cd43fe0b98973af354706268c89828b88ece5e497"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 89 D8 48 83 C8 01 EB 04 48 8B 76 10 48 3B 46 08 72 F6 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_dd0d6173 {
    meta:
        id = "2QLMaDS9e9ovUQp4GES9Rq"
        fingerprint = "v1_sha256_7061edef1981e2b93bcdd8be47c0f6067acc140a543eed748bf0513f182e0a59"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 F8 8B 45 F0 89 42 0C 48 8B 55 F8 8B 45 F4 89 42 10 C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_779e142f {
    meta:
        id = "6CVbqXQ24AT8WdyO2C8sjl"
        fingerprint = "v1_sha256_80ba5a1cf333fafc6a1d7823ca4a8d5c30c1c07a01d6d681c22dd29e197089f1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_cf84c9f2 {
    meta:
        id = "3H6m02En8TpXlkfsiBwMa0"
        fingerprint = "v1_sha256_9af164ece7e7e0f33dc32f18735a8f655593ae6cde34e05108f3221b71aa8676"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 48 89 E5 48 83 EC 30 48 89 7D E8 89 75 E4 89 55 E0 C7 45 F8 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0cd591cd {
    meta:
        id = "4XY8XjH959VPKqClxpnoal"
        fingerprint = "v1_sha256_4300bdd173dfb33ca34c0f2fe4fa6ee071e99d5db201262e914721aad0ad433b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4E F8 48 8D 4E D8 49 8D 42 E0 48 83 C7 03 EB 6B 4C 8B 46 F8 48 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_859042a0 {
    meta:
        id = "1CUmfV96o02LtZg1j6AOY9"
        fingerprint = "v1_sha256_b8daa4a136a6511472703687fe56fbca2bd005a1373802a46c8d211b6d039d75"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "41615d3f3f27f04669166fdee3996d77890016304ee87851a5f90804d6d4a0b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 A8 48 83 C0 01 48 89 45 C0 EB 05 48 83 45 C0 01 48 8B 45 C0 0F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_33b4111a {
    meta:
        id = "7Nu92VzrwpvVEzRKfGdOLa"
        fingerprint = "v1_sha256_a08c0f7be26e2e9abfaa392712895bb3ce1d12583da4060ebe41e1a9c1491b7c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C1 83 E1 0F 74 1A B8 10 00 00 00 48 29 C8 48 8D 0C 02 48 89 DA 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_4f43b164 {
    meta:
        id = "6T0aUkVSfojSgTmAuhN9Lu"
        fingerprint = "v1_sha256_79a17e70e9b7af6e53f62211c33355a4c46a82e7c4e80c20ffe9684e24155808"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "f0fdb3de75f85e199766bbb39722865cac578cde754afa2d2f065ef028eec788"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 46 00 4B 49 4C 4C 53 55 42 00 4B 49 4C 4C 53 55 42 20 3C 73 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e4a1982b {
    meta:
        id = "4OuBVEd2h55QsUZedB1ysj"
        fingerprint = "v1_sha256_4cd7aa205b3571cffca208e315d6311fa92a5993e2a8e40d342d6184811f42f0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 45 EC F7 D0 21 D0 33 45 FC C9 C3 55 48 89 E5 48 83 EC 30 48 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_862c4e0e {
    meta:
        id = "39RuU3M8z2tbuzCgdc7bSo"
        fingerprint = "v1_sha256_a1dce44e76f9d2a517c4849c58dfecb07e1ef0d78fddff10af601184d636583f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 02 89 45 F8 8B 45 F8 C1 E8 10 85 C0 75 E6 8B 45 F8 F7 D0 0F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9127f7be {
    meta:
        id = "3mjmNsflwUNIsdOHIV6hOG"
        fingerprint = "v1_sha256_2b1fa115598561e081dfb9b5f24f6728b0d52cb81ac7933728d81646f461bcae"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E4 F7 E1 89 D0 C1 E8 03 89 45 E8 8B 45 E8 01 C0 03 45 E8 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0e03b7d3 {
    meta:
        id = "2JX00YmaaTRtZQrXgQHixA"
        fingerprint = "v1_sha256_845be03fac893f8e914aabda5206000dc07947ade0b8f46cc5d58d8458f035f6"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F5 74 84 32 63 29 5A B2 78 FF F7 FA 0E 51 B3 2F CD 7F 10 FA }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_32eb0c81 {
    meta:
        id = "5Zb2UakIuHuBghp3jKpY4p"
        fingerprint = "v1_sha256_a06d9e1190ba79b0e19cab7468f01a49359629a6feb27b7d72f3d1d52d1483d7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D4 48 FF 45 F0 48 8B 45 F0 0F B6 00 84 C0 75 DB EB 12 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9abf7e0c {
    meta:
        id = "21Z7IgyKy7EpgXU7uSwf6M"
        fingerprint = "v1_sha256_00276330e388d07368577c4134343cb9fc11957dba6cff5523331199f1ed04aa"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 E0 0F B6 42 0D 83 C8 01 88 42 0D 48 8B 55 E0 0F B6 42 0D 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_33801844 {
    meta:
        id = "1a76mmp8eaC9eQwSW323EN"
        fingerprint = "v1_sha256_20b8ebce14776e48310be099afd0dca0f28778d0024318b339b75e2689f70128"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "2ceff60e88c30c02c1c7b12a224aba1895669aad7316a40b575579275b3edbb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 F8 48 83 E8 01 0F B6 00 3C 0D 75 0B 48 8B 45 F8 0F B6 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a33a8363 {
    meta:
        id = "6FV9FGDyHshWbRX7P4CbT7"
        fingerprint = "v1_sha256_3fe17dc43f07dacdad6ababf141983854b977e244c0af824fea0ab953ad70fee"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 88 02 48 85 D2 75 ED 5A 5B 5D 41 5C 41 5D 4C 89 F0 41 5E }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9a62845f {
    meta:
        id = "7QgVBpVrAlZ0n5ZbC5oPbq"
        fingerprint = "v1_sha256_b3ab125c8bfb5b7a0be0e92cf5a50057e403ab3597698ec2e7a8bafa0d3a8b80"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "f67f8566beab9d7494350923aceb0e76cd28173bdf2c4256e9d45eff7fc8cb41"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 83 F8 20 7F 1E 83 7D 08 07 75 33 8B 45 0C 83 C0 18 8B 00 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_4d81ad42 {
    meta:
        id = "5MXTr8PKXHnl374AragRIp"
        fingerprint = "v1_sha256_57b54eed37690949ba2d4eff713691f16f00207d7b374beb7dfa2e368588dbb0"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "3021a861e6f03df3e7e3919e6255bdae6e48163b9a8ba4f1a5c5dced3e3e368b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 44 C8 07 0B BF F1 1B 7E 83 CD FF 31 DB 2E 22 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6a510422 {
    meta:
        id = "1pqcbPxaPb3uqeOu7GN9cY"
        fingerprint = "v1_sha256_4384536817bf5df223d4cf145892b7714f2dbd1748930b6cd43152d4e35c9e56"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0B E5 24 30 1B E5 2C 30 0B E5 1C 00 00 EA 18 30 1B E5 00 30 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d2953f92 {
    meta:
        id = "3BUifMQpg5vq5P7Km1V77f"
        fingerprint = "v1_sha256_d0af462d26f6ffe469c57d63f1f7d551e3fb9cc39c7e4c35b3e71f659c01c076"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 1B E5 2A 00 53 E3 0A 00 00 0A 30 30 1B E5 3F 00 53 E3 23 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6ae4b580 {
    meta:
        id = "37UdfNYqC7JOPGLhk3V3yA"
        fingerprint = "v1_sha256_eb0fe44df1c995c5d4e3a361c3e466f78cb70bffbc76d1b7b345ee651b313b9e"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 30 0B E5 3C 20 1B E5 6C 32 1B E5 03 00 52 E1 01 00 00 DA 6C }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d608cf3b {
    meta:
        id = "1i95D3aw9LBu8Q6BLMV8BG"
        fingerprint = "v1_sha256_ad5b7d32c85adc7f778a8f4815e595b90a6f15dec048bcf97c6ab179582eb4f7"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF 2F E1 7E 03 00 00 78 D8 00 00 24 00 00 00 28 00 00 00 4C }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_3f8cf56e {
    meta:
        id = "VXiPjAlMjdUhNOjG4j8yh"
        fingerprint = "v1_sha256_b2cf8b1913a88e6a6346f0ac8cd2e7c33b41d44bf60ff7327ae40a2d54748bd9"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "1878f0783085cc6beb2b81cfda304ec983374264ce54b6b98a51c09aea9f750d"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 2F DA E8 E9 CC E4 F4 39 55 E2 9E 33 0E C0 F0 FB 26 93 31 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fb14e81f {
    meta:
        id = "Ys8m6uBracR2ejR8GDXPY"
        fingerprint = "v1_sha256_2efb958c269640c374485502611372f4404cf35d7ab704d20ce37b8c1f69645d"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "0fd07e6068a721774716eb4940e2c19faef02d5bdacf3b018bf5995fa98a3a27"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4E 45 52 00 53 43 41 4E 4E 45 52 20 4F 4E 20 7C 20 4F 46 46 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e09726dc {
    meta:
        id = "6MyWuRu0hoOTEpYTiqqNh6"
        fingerprint = "v1_sha256_ebd00e593a7fcd46e36fd0ca213e1f82c0f4a94448b6fd605d35cea45a490493"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "1e64187b5e3b5fe71d34ea555ff31961404adad83f8e0bd1ce0aad056a878d73"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 48 83 EC 08 48 83 C4 08 C3 00 00 00 01 00 02 00 50 49 4E 47 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ad12b9b6 {
    meta:
        id = "1DTAKxa3fbOM6PibXkZgOB"
        fingerprint = "v1_sha256_72a85d14eb8ab78364ea2e8b89d9409c0046b14602f4a3415d829f4985fb2de3"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "f0411131acfddb40ac8069164ce2808e9c8928709898d3fb5dc88036003fe9c8"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4C 52 46 00 4B 45 46 31 4A 43 53 00 4B 45 46 31 51 45 42 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0535ebf7 {
    meta:
        id = "3MgeAH0LZGFfb7js0KrE41"
        fingerprint = "v1_sha256_eb574468e9d371def0da74e6aba827272181399a84388a14ffb167ec6ebd40d1"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "77e18bb5479b644ba01d074057c9e2bd532717f6ab3bb88ad2b7497b85d2a5de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 48 8B 04 24 6A 18 48 F7 14 24 48 FF 04 24 48 03 24 24 48 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_32a7edd2 {
    meta:
        id = "3bgCcVCLAKuM6trDhyFE8W"
        fingerprint = "v1_sha256_af26549c1cad0975735e2c233bc71e5e1b0e283d02552fdaea02656332ecd854"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 75 FD 48 FD 45 FD 0F FD 00 FD FD 0F FD FD 02 00 00 48 FD 45 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d7f35b54 {
    meta:
        id = "4S1Dwz44PCBsg1tV9HJQDw"
        fingerprint = "v1_sha256_d827e21c09b8dce65db293aa57b39f49f034537bb708471989ad64e653c479be"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FD 48 FD 45 FD 48 FD FD FD FD FD FD FD FD FD 48 FD 45 FD 66 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f11e98be {
    meta:
        id = "4w5REzvvfkdIxKZZTRgyra"
        fingerprint = "v1_sha256_9b9122f0897610dff6b37446b3cecbfcec3dce8dc7e1934e78cc32d5f6ac9648"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FD 40 00 09 FD 21 FD FD 08 48 FD 80 3E 00 75 FD FD 4C 24 48 0F FD }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_8d4e4f4a {
    meta:
        id = "4mwZP5Yy3cjBiovwZBGTsI"
        fingerprint = "v1_sha256_11ee101a936f8e6949701e840ef48a0fe102099ea3b71c790b9a5128e5c59029"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 50 00 FD FD 00 00 00 31 FD 48 FD FD 01 00 00 00 49 FD FD 04 }
    condition:
        all of them
}

