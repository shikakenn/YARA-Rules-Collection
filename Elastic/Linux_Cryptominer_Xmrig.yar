rule Linux_Cryptominer_Xmrig_57c0c6d7 {
    meta:
        id = "7AGKsIPv00dFJoo15BRXEB"
        fingerprint = "v1_sha256_d3a272d488cebe4f774c994001a14d825372a27f16267bc0339b7e3b22ada8db"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "100dc1ede4c0832a729d77725784d9deb358b3a768dfaf7ff9e96535f5b5a361"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 78 01 66 0F EF C9 49 89 38 0F BE 00 83 E8 30 F2 0F 2A C8 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_7e42bf80 {
    meta:
        id = "4Cccm11PmtU1E9vEqDgo16"
        fingerprint = "v1_sha256_ad8c8f0081d07f7e2a5400de6af2c6b311f77ff336d7576f7fb0bfe2593a9062"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "551b6e6617fa3f438ec1b3bd558b3cbc981141904cab261c0ac082a697e5b07d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F 70 F8 FF 66 0F 73 FD 04 66 44 0F EF ED 66 41 0F 73 FE 04 66 41 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_271121fb {
    meta:
        id = "3P6AIOjM36LoNBSFZ8UZGT"
        fingerprint = "v1_sha256_f43b1527ad4bbd07023126def89c1af47698cc832f71f4a1381ed0d621d79ed5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "19aeafb63430b5ac98e93dfd6469c20b9c1145e6b5b86202553bd7bd9e118842"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 18 41 C1 E4 10 C1 E1 08 41 C1 EA 10 44 89 CB 41 C1 E9 18 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_e7e64fb7 {
    meta:
        id = "4ZzE11UxkvQx2CwQs4Oc2Y"
        fingerprint = "v1_sha256_e325ac02c51526c5a36bdd6c2bcb3bee51f1214d78eff8048c8a1ae88334a9e8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 03 48 89 74 24 48 77 05 48 8B 5C C4 30 4C 8B 0A 48 8B 0F 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_79b42b21 {
    meta:
        id = "2UgcQC7rKAjedqwaYbmj6E"
        fingerprint = "v1_sha256_db42871193960ea4c2cbe5f5040cbc1097d57d9e4dc291bcc77ed72b588311ab"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FC 00 79 0A 8B 45 B8 83 E0 04 85 C0 75 38 8B 45 EC 83 C0 01 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_77fbc695 {
    meta:
        id = "36O9b9uvBcsoRHQGwlCiOb"
        fingerprint = "v1_sha256_af8e09cd5d6b7532af0c06273aa465cf6c40ad6c919a679fd09191a1c2a302f5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "e723a2b976adddb01abb1101f2d3407b783067bec042a135b21b14d63bc18a68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F2 0F 58 44 24 08 F2 0F 11 44 24 08 8B 7B 08 41 8D 76 01 49 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_403b0a12 {
    meta:
        id = "5l3dQGoCm7XKX61ZjmotKd"
        fingerprint = "v1_sha256_5b7662124eb980b11f88a50665292e7a405595f7ad85c5c448dd087ea096689a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "54d806b3060404ccde80d9f3153eebe8fdda49b6e8cdba197df0659c6724a52d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 28 03 1C C3 0C 00 C0 00 60 83 1C A7 71 00 00 00 68 83 5C D7 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_bffa106b {
    meta:
        id = "4sJzBYXpO4nOQzDQ81cxcE"
        fingerprint = "v1_sha256_d7214ad9c4291205b50567d142d99b8a19a9cfa69d3cd0a644774c3a1adb6b49"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 24 9C 44 0F B6 94 24 BC 00 00 00 89 5C 24 A0 46 8B 0C 8A 66 0F 6E 5C }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_73faf972 {
    meta:
        id = "4L2u1RXND3vvKR84vG26q7"
        fingerprint = "v1_sha256_a6a9d304d215302bf399c90ed0dd77a681796254c51a2a20e4a316dba43b387f"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6F C4 83 E0 01 83 E1 06 09 C1 44 89 E8 01 C9 D3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_af809eea {
    meta:
        id = "1mzw9dnSLNRHW2a0LquBoK"
        fingerprint = "v1_sha256_4ae4b119a3eecfdb47a88fe5a89a4f79ae96eecf5d08eef08997357de7e6538a"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 E0 01 83 E1 06 09 C1 44 89 ?? 01 C9 D3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_9f6ac00f {
    meta:
        id = "4CS6ea83wdT8oe88h5iIrc"
        fingerprint = "v1_sha256_9fa8e7be5c35c9a649c42613d0d5d5cecff3d9c3e9a572e4be1ca661876748a5"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "9cd58c1759056c0c5bbd78248b9192c4f8c568ed89894aff3724fdb2be44ca43"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B8 31 75 00 00 83 E3 06 09 D9 01 C9 D3 F8 89 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_dbcc9d87 {
    meta:
        id = "7SP6kyPUtp19nyqOQZG3f8"
        fingerprint = "v1_sha256_b7fa60e32cb53484d8b76b13066eda1f2275ee2660ac2dc02b0078b921998e79"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "da9b8fb5c26e81fb3aed3b0bc95d855339fced303aae2af281daf0f1a873e585"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 78 72 47 47 58 34 53 58 5F 34 74 43 41 66 30 5A 57 73 00 64 48 8B 0C 25 F8 FF }
    condition:
        all of them
}

