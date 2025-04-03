rule Linux_Cryptominer_Malxmr_d13544d7 {
    meta:
        id = "5slGbYSWB3hjloFpg7AOKx"
        fingerprint = "v1_sha256_fcb2fc7a84fbcd23f9a9d9fd2750c45ff881689670a373fce0cc444183d11999"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 51 50 4D 21 EB 4B 8D 0C 24 4C 89 54 24 90 4C 89 DD 48 BA AA AA AA AA AA AA }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_ad09e090 {
    meta:
        id = "2TBAsrupbclUO8naYYT5Wd"
        fingerprint = "v1_sha256_6c2d548ba9f01444e8fe4b0aa8a0556970acac06d39bb7c87446b6b91ab0d129"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 50 8B 44 24 64 89 54 24 54 39 C3 77 0E 72 08 8B 44 24 60 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_12299814 {
    meta:
        id = "1GNYZTWtvGOsmojY9Oay1c"
        fingerprint = "v1_sha256_52e8bcd0512cedf0fa048b6990a5d331f4302d99b00681c83a76587415894b1e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "eb3802496bd2fef72bd2a07e32ea753f69f1c2cc0b5a605e480f3bbb80b22676"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 3C 40 00 83 C4 10 89 44 24 04 80 7D 00 00 74 97 83 EC 0C 89 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_a47b77e4 {
    meta:
        id = "3MHmrx0LJjRDCEMwtU6ls6"
        fingerprint = "v1_sha256_bd2b14c8b8e2649af837224fadb32bf0fb67ac403189063a8cb10ad344fb8015"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "995b43ccb20343494e314824343a567fd85f430e241fdeb43704d9d4937d76cc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8D 48 49 5E 97 87 DC 73 86 19 51 B3 36 1A 6E FC 8C CC 2C 6E 0B }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_21d0550b {
    meta:
        id = "405RwaXWDgGurNQGVyOihM"
        fingerprint = "v1_sha256_c9a12eee281b1e944b5572142c5e18ff087989f45026a94268df22d483210178"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 3B 31 C0 48 83 C9 FF 48 89 EE F2 AE 48 8B 3B 48 F7 D1 48 FF C9 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_c8adb449 {
    meta:
        id = "6nIYqeIMEQg5JK75bIBjVr"
        fingerprint = "v1_sha256_9c43602dc752dd737a983874bee5ec6af145ce5fdd45d03864a1afdc2aec3ad4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "00ec7a6e9611b5c0e26c148ae5ebfedc57cf52b21e93c2fe3eac85bf88edc7ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D2 4C 89 54 24 A0 4C 89 FA 48 F7 D2 48 23 54 24 88 49 89 D2 48 8B 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_bcab1e8f {
    meta:
        id = "68lPuvDLY9tFjhP4gHMf4H"
        fingerprint = "v1_sha256_72643b2860f40c7e901c671d7cc9992870b91912df5d75d2ffba0dfb8684f8d3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "19df7fd22051abe3f782432398ea30f8be88cf42ef14bc301b1676f35b37cd7e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EB D9 D3 0B EB D5 29 0B EB D1 03 48 6C 01 0B EB CA 0F AF 0B }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_6671f33a {
    meta:
        id = "TKE6OQWjnmBbPlyMiiNG2"
        fingerprint = "v1_sha256_a15c842c7c7ec3b11183a1502f8ec03ea786e3f0d47fbab58c62ffff7b018030"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4D 18 48 01 4B 18 5A 5B 5D C3 83 C8 FF C3 48 85 FF 49 89 F8 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_74418ec5 {
    meta:
        id = "5ZZuoRVxTjIftnFxJNos6z"
        fingerprint = "v1_sha256_e74463f53611baaec7c8e126218d8353c6e3a5e71c20e98a7035df6b771b690b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "d79ad967ac9fc0b1b6d54e844de60d7ba3eaad673ee69d30f9f804e5ccbf2880"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F9 75 7A A8 8A 65 FC 5C E0 6E 09 4B 8F AA B3 A4 66 44 B1 D1 13 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_979160f6 {
    meta:
        id = "2XivLb4PXaM4qjzI8SsxFd"
        fingerprint = "v1_sha256_e70097fb263c90576e87e76cc7be391dbf9c9d73bbd7fb8e5ec282e6ac1f648d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E0 08 C1 ED 10 41 31 C3 89 D8 45 09 D0 C1 E8 10 C1 E3 10 41 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_fe7139e5 {
    meta:
        id = "3ntX4uVZ4QrhsrxbKfoM2K"
        fingerprint = "v1_sha256_d1ef74f2a74950845091b2ebc2f7fd05980bcbd2aea4fdd9549c54cec1768501"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "8b13dc59db58b6c4cd51abf9c1d6f350fa2cb0dbb44b387d3e171eacc82a04de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF 74 5B 48 29 F9 49 89 DC 4C 8D 69 01 49 D1 ED 4C 01 E9 4D 8D 6C }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_f35a670c {
    meta:
        id = "d8n7yT4bi7c1VNWX7mUOo"
        fingerprint = "v1_sha256_95a8aeffb7193c3f4adfea5b7f0741a53528620c57cbdb4d471d756db03c6493"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "a73808211ba00b92f8d0027831b3aa74db15f068c53dd7f20fcadb294224f480"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4C 01 CD 48 0F AF D6 48 8D 54 55 00 89 DD 48 31 D7 48 C1 C7 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_70e5946e {
    meta:
        id = "3S3yVqqHHwpd8T4T9tIQsq"
        fingerprint = "v1_sha256_324deafee2b14c125100e49b90ea95bc1fc55020a7e81a69c7730a57430560f4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4F 70 48 8D B4 24 B0 00 00 00 48 89 34 CA 49 8B 57 68 48 89 C8 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_033f06dd {
    meta:
        id = "5nx3zzre9yyh6vlRFTeCrz"
        fingerprint = "v1_sha256_a0c788dbcd43cab2af1614d5d90ed9e07a45b547241f729e09709d2a1ec24e60"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 42 68 63 33 4E 33 5A 48 78 6A 64 58 51 67 4C 57 51 36 49 43 31 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_ce0c185f {
    meta:
        id = "5tdiDocmFDB9XfAITXIM84"
        fingerprint = "v1_sha256_f88c5a295cc62f5a91e26731fc60aaf450376cbb282f43304ba2a5ac5d149dd4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EF E5 66 0F 6F AC 24 80 00 00 00 66 0F EB E8 66 0F EF D5 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_da08e491 {
    meta:
        id = "2EUjnuDXlXRKziCBRUtlhM"
        fingerprint = "v1_sha256_f98252c33f8d76981bbc51de87a11a7edca7292a864fc2a305d29cd21961729e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "4638d9ece32cd1385121146378772d487666548066aecd7e40c3ba5231f54cc0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F9 48 31 CD 48 89 F9 48 F7 D1 4C 21 F9 48 21 DA 49 31 CA 48 }
    condition:
        all of them
}

