rule Linux_Generic_Threat_a658b75f {
    meta:
        id = "4JfKYlE3xgBzfqVjvQqoJ1"
        fingerprint = "v1_sha256_1ef7267438b8d15ed770f0784a7d428cbc2680144b0ef179337875d5b4038d08"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "df430ab9f5084a3e62a6c97c6c6279f2461618f038832305057c51b441c648d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 6D 61 69 6E 2E 45 6E 63 72 79 70 74 46 69 6C 65 52 65 61 64 57 72 69 74 65 }
        $a2 = { 6D 61 69 6E 2E 53 63 61 6E 57 61 6C 6B 65 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_ea5ade9a {
    meta:
        id = "1ZZAvqPFUbjZ5ed7rcAVWw"
        fingerprint = "v1_sha256_12a9b5e54d6d528ecb559b6e2ea3aa72effa7f0efbf2c33581a4efedc292e4c1"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d75189d883b739d9fe558637b1fab7f41e414937a8bae7a9d58347c223a1fcaa"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 55 89 E5 53 8B 5D 08 B8 0D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 B8 2D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 8B 4D 0C B8 6C 00 00 00 CD 80 8B 5D FC 89 EC }
    condition:
        all of them
}

rule Linux_Generic_Threat_80aea077 {
    meta:
        id = "6CVFxAIgMtB7zouiusFz5I"
        fingerprint = "v1_sha256_cab860ad5f0c49555adb845504acb4dbeabb94dbc287202be35020e055e6f27b"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "002827c41bc93772cd2832bc08dfc413302b1a29008adbb6822343861b9818f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 38 49 89 FE 0F B6 0E 48 C1 E1 18 0F B6 6E 01 48 C1 E5 10 48 09 E9 0F B6 6E 03 48 09 E9 0F B6 6E 02 48 C1 E5 08 48 09 CD 0F B6 56 04 48 C1 E2 18 44 0F B6 7E 05 49 C1 E7 10 4C 09 FA 44 }
    condition:
        all of them
}

rule Linux_Generic_Threat_2e214a04 {
    meta:
        id = "1OKAhXJD9D0OT6RCKMl4Kx"
        fingerprint = "v1_sha256_0d29aa6214b0a05f9af10cdc080ffa33452156e13c057f31997630cebcda294a"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cad65816cc1a83c131fad63a545a4bd0bdaa45ea8cf039cbc6191e3c9f19dead"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 49 6E 73 65 72 74 20 76 69 63 74 69 6D 20 49 50 3A 20 }
        $a2 = { 49 6E 73 65 72 74 20 75 6E 75 73 65 64 20 49 50 3A 20 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0b770605 {
    meta:
        id = "5zhGR6Qw7PRonJd91aT1o7"
        fingerprint = "v1_sha256_d4aae755870765a119ee7ae648d4388e0786e8ab6f7f196d81c6356be7d0ddfb"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "99418cbe1496d5cd4177a341e6121411bc1fab600d192a3c9772e8e6cd3c4e88"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 68 65 79 20 73 63 61 6E 20 72 65 74 61 72 64 }
        $a2 = { 5B 62 6F 74 70 6B 74 5D 20 43 6F 6D 6D 69 74 74 69 6E 67 20 53 75 69 63 69 64 65 }
    condition:
        all of them
}

rule Linux_Generic_Threat_92064b27 {
    meta:
        id = "kSqYrbBidLmIeERuEWkFE"
        fingerprint = "v1_sha256_adb9ed7280065f77440bd1e106bc800ebe6251119151cd54b76dc2917b013f65"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "8e5cfcda52656a98105a48783b9362bad22f61bcb6a12a27207a08de826432d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 55 89 E5 53 8B 4D 10 8B 5D 08 85 C9 74 0D 8A 55 0C 31 C0 88 14 18 40 39 C1 75 F8 5B 5D C3 90 90 55 89 E5 8B 4D 08 8B 55 0C 85 C9 74 0F 85 D2 74 0B 31 C0 C6 04 08 00 40 39 C2 75 F7 5D C3 90 90 }
    condition:
        all of them
}

rule Linux_Generic_Threat_de6be095 {
    meta:
        id = "6AAvSLoOolWGKrFpJYPJ6Q"
        fingerprint = "v1_sha256_cbd7578830169703b047adb1785b05d226f2507a65c203ee344d8e2b3a24f6c9"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2431239d6e60ca24a5440e6c92da62b723a7e35c805f04db6b80f96c8cf9fee6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 2D 2D 66 61 72 6D 2D 66 61 69 6C 6F 76 65 72 }
        $a2 = { 2D 2D 73 74 72 61 74 75 6D 2D 66 61 69 6C 6F 76 65 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_898d9308 {
    meta:
        id = "5uXlI2NoJgU1mHlXNK0Mfw"
        fingerprint = "v1_sha256_8b5deedf18d660d0b76dc987843ff5cc01432536a04ab4925e9b08269fd847e4"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "ce89863a16787a6f39c25fd15ee48c4d196223668a264217f5d1cea31f8dc8ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 65 63 66 61 66 65 61 62 36 65 65 37 64 36 34 32 }
        $a2 = { 3D 3D 3D 3D 65 6E 64 20 64 75 6D 70 20 70 6C 75 67 69 6E 20 69 6E 66 6F 3D 3D 3D 3D }
    condition:
        all of them
}

rule Linux_Generic_Threat_23d54a0e {
    meta:
        id = "4E2lNl5U60bDqkKV1QRCqW"
        fingerprint = "v1_sha256_7e52eaf9c49bd6cbdb89b0c525b448864e1ea55d00bc052898613174fe5956cc"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 29 2B 2F 30 31 3C 3D 43 4C 4D 50 53 5A 5B }
        $a2 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }
    condition:
        all of them
}

rule Linux_Generic_Threat_d7802b0a {
    meta:
        id = "7haYypP86noJPMkpPTnGlt"
        fingerprint = "v1_sha256_3e1452204fef11d63870af5f143ae73f4b8e5a4db83a53851444fbf8a0ea6a26"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 48 81 EC 88 00 00 00 48 89 AC 24 80 00 00 00 48 8D AC 24 80 00 00 00 49 C7 C5 00 00 00 00 4C 89 6C 24 78 88 8C 24 A8 00 00 00 48 89 9C 24 A0 00 00 00 48 89 84 24 98 00 00 00 C6 44 24 27 00 90 }
    condition:
        all of them
}

rule Linux_Generic_Threat_08e4ee8c {
    meta:
        id = "3kdxeT1nmAqbPrVWxuVSPK"
        fingerprint = "v1_sha256_a927415afbab32adee49a583fc35bc3d44764f87bbbb3497b38af6feb92cd9a8"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "35eeba173fb481ac30c40c1659ccc129eae2d4d922e27cf071047698e8d95aea"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 78 63 72 79 70 74 6F 67 72 61 70 68 79 2D 32 2E 31 2E 34 2D 70 79 32 2E 37 2E 65 67 67 2D 69 6E 66 6F 2F 50 4B 47 2D 49 4E 46 4F }
    condition:
        all of them
}

rule Linux_Generic_Threat_d60e5924 {
    meta:
        id = "2OBQWDLx0DEmHI7DdTCZuL"
        fingerprint = "v1_sha256_012111e4a38c1f901dcd830cc26ef8dcfbde7986fcc8b8eebddb8d8b7a0cec6a"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "fdcc2366033541053a7c2994e1789f049e9e6579226478e2b420ebe8a7cebcd3"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 2E 2F 6F 76 6C 63 61 70 2F 6D 65 72 67 65 2F 6D 61 67 69 63 }
        $a2 = { 65 78 65 63 6C 20 2F 62 69 6E 2F 62 61 73 68 }
    condition:
        all of them
}

rule Linux_Generic_Threat_6bed4416 {
    meta:
        id = "4reD18aMaGjkChA3E1QnOs"
        fingerprint = "v1_sha256_c098e27a12d5d10af67d1b78572bc7daeb500504527428366e1d9a4e55e0f4d7"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }
    condition:
        all of them
}

rule Linux_Generic_Threat_fc5b5b86 {
    meta:
        id = "44DQQt9pCBCk3YClCv6BxR"
        fingerprint = "v1_sha256_a11ed323df7283188cf99ca89abbd18673fef88660df1150d4dc72de04a836a8"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "134b063d9b5faed11c6db6848f800b63748ca81aeca46caa0a7c447d07a9cd9b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 74 1D 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 92 98 05 00 8B 44 24 }
    condition:
        all of them
}

rule Linux_Generic_Threat_2c8d824c {
    meta:
        id = "3XdwbOYeBPumWg0WMbEMYN"
        fingerprint = "v1_sha256_c8fc90ec5e93ff39443f513e83f34140819a30b737da2a412ba97a7b221ca9dc"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "9106bdd27e67d6eebfaec5b1482069285949de10afb28a538804ce64add88890"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 38 48 89 5C 24 50 48 89 7C 24 60 48 89 4C 24 58 48 8B 10 48 8B 40 08 48 8B 52 28 FF D2 48 89 44 24 28 48 89 5C 24 18 48 8B 4C 24 50 31 D2 90 EB 03 48 FF C2 48 39 D3 7E 6C 48 8B 34 D0 }
    condition:
        all of them
}

rule Linux_Generic_Threat_936b24d5 {
    meta:
        id = "5JJROBOjs0iN0vVZIzTkDt"
        fingerprint = "v1_sha256_972bbc4950c49ff7bc880b1d24b586072eb8541584b97a00ac501fac133a3157"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "fb8eb0c876148a4199cc873b84fd9c1c6abc1341e02d118f72ffb0dae37592a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 66 73 65 65 6B 6F 28 6F 70 74 2E 64 69 63 74 2C 20 30 4C 2C 20 53 45 45 4B 5F 45 4E 44 29 20 21 3D 20 2D 31 }
    condition:
        all of them
}

rule Linux_Generic_Threat_98bbca63 {
    meta:
        id = "6t4RkAjb5afRBBacDRmh2f"
        fingerprint = "v1_sha256_1728d47b3f364cff02ae61ccf381ecab0c1fe46a5c76d832731fdf7acc1caf55"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "1d4d3d8e089dcca348bb4a5115ee2991575c70584dce674da13b738dd0d6ff98"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 64 65 73 63 72 69 70 74 69 6F 6E 3D 4C 4B 4D 20 72 6F 6F 74 6B 69 74 }
        $a2 = { 61 75 74 68 6F 72 3D 6D 30 6E 61 64 }
    condition:
        all of them
}

rule Linux_Generic_Threat_9aaf894f {
    meta:
        id = "7VrSlQPMzL6aDFw2hxut1i"
        fingerprint = "v1_sha256_b28d6a8c23aba4371e2e5f48861d2bcc8bdfa7212738eda7b1b4a3059d159cf2"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "467ac05956eec6c74217112721b3008186b2802af2cafed6d2038c79621bcb08"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 2F 62 69 6E 2F 63 70 20 2F 74 6D 70 2F 70 61 6E 77 74 65 73 74 20 2F 75 73 72 2F 62 69 6E 2F 70 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_ba3a047d {
    meta:
        id = "RWEIzs1DMDzIDtLPB2Ll8"
        fingerprint = "v1_sha256_ffcfb90c0c796b7b343adbd2142193759ececddd0700c0bb4e2898947464b1a2"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3064e89f3585f7f5b69852f1502e34a8423edf5b7da89b93fb8bd0bef0a28b8b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 52 65 61 64 69 6E 67 20 61 74 20 6D 61 6C 69 63 69 6F 75 73 5F 78 20 3D 20 25 70 2E 2E 2E 20 }
        $a2 = { 28 73 65 63 6F 6E 64 20 62 65 73 74 3A 20 30 78 25 30 32 58 20 73 63 6F 72 65 3D 25 64 29 }
    condition:
        all of them
}

rule Linux_Generic_Threat_902cfdc5 {
    meta:
        id = "1bafixIJ3GCL7V5D4HjBYS"
        fingerprint = "v1_sha256_0f86914cb598262744660e65048f75d071307ae47d069971bfcd049a7d4b36e5"
        version = "1.0"
        date = "2024-01-23"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 54 65 67 73 6B 54 47 66 42 7A 4C 35 5A 58 56 65 41 54 4A 5A 2F 4B 67 34 67 47 77 5A 4E 48 76 69 5A 49 4E 50 49 56 70 36 4B 2F 2D 61 77 33 78 34 61 6D 4F 57 33 66 65 79 54 6F 6D 6C 71 37 2F 57 58 6B 4F 4A 50 68 41 68 56 50 74 67 6B 70 47 74 6C 68 48 }
    condition:
        all of them
}

rule Linux_Generic_Threat_094c1238 {
    meta:
        id = "7OiMzcYXm6l438vhMTimxg"
        fingerprint = "v1_sha256_fb82e16bf153c88377cc8655557bc1f021af6e04e1160129ce9555e078d00a0d"
        version = "1.0"
        date = "2024-01-23"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2bfe7d51d59901af345ef06dafd8f0e950dcf8461922999670182bfc7082befd"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 48 81 EC 18 01 00 00 48 89 D3 41 89 F6 49 89 FF 64 48 8B 04 25 28 00 00 00 48 89 84 24 10 01 00 00 49 89 E4 4C 89 E7 E8 FD 08 00 00 48 89 DF E8 75 08 00 00 4C 89 E7 48 89 DE 89 C2 E8 F8 08 00 }
    condition:
        all of them
}

rule Linux_Generic_Threat_a8faf785 {
    meta:
        id = "5GW7MaxvAKvYCf3vEkE4Ab"
        fingerprint = "v1_sha256_3ab5d9ba39be2553173f6eb4d2a1ca22bfb9f1bd537fed247f273eba1eabd782"
        version = "1.0"
        date = "2024-01-23"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "6028562baf0a7dd27329c8926585007ba3e0648da25088204ebab2ac8f723e70"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 55 89 E5 53 57 56 83 E4 F0 83 EC 10 E8 00 00 00 00 5B 81 C3 53 50 00 00 8B 45 0C 8B 4D 10 8B 55 08 65 8B 35 14 00 00 00 89 74 24 08 8D 75 14 89 74 24 04 8B 3A 56 51 50 52 FF 97 CC 01 00 00 83 }
    condition:
        all of them
}

rule Linux_Generic_Threat_04e8e4a5 {
    meta:
        id = "6dsC9EaoyreEHlScehPepW"
        fingerprint = "v1_sha256_9b04725bf0a75340c011028b201ed08eb9de305a5b4630cc79156c0a847cdc9e"
        version = "1.0"
        date = "2024-01-23"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "248f010f18962c8d1cc4587e6c8b683a120a1e838d091284ba141566a8a01b92"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 48 81 EC F8 01 00 00 48 8D 7C 24 10 E8 60 13 00 00 48 8D 7C 24 10 E8 12 07 00 00 85 ED 74 30 48 8B 3B 48 8D 54 24 02 48 B8 5B 6B 77 6F 72 6B 65 72 BE 0D 00 00 00 48 89 44 24 02 C7 44 24 0A 2F }
    condition:
        all of them
}

rule Linux_Generic_Threat_47b147ec {
    meta:
        id = "3F6L2QBXPLzU58V2PxS7p8"
        fingerprint = "v1_sha256_84c68f2ed76d644122daf81d41d4eb0be9aa8b1c82993464d3138ae30992110f"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cc7734a10998a4878b8f0c362971243ea051ce6c1689444ba6e71aea297fb70d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 50 41 54 48 3D 2F 62 69 6E 3A 2F 73 62 69 6E 3A 2F 75 73 72 2F 73 62 69 6E 3A 2F 75 73 72 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 73 62 69 6E }
    condition:
        all of them
}

rule Linux_Generic_Threat_887671e9 {
    meta:
        id = "Az2JOU0fO0dDjlJebvnij"
        fingerprint = "v1_sha256_eefe9391a9ce716dbe16f11b8ccea89d032fdad42fcabd84ffe584409c550847"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "701c7c75ed6a7aaf59f5a1f04192a1f7d49d73c1bd36453aed703ad5560606dc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 55 89 E5 57 56 53 83 E4 F0 83 EC 40 8B 45 0C E8 DC 04 00 00 81 C3 AC F7 0B 00 89 44 24 04 8B 45 08 89 04 24 E8 A7 67 00 00 85 C0 0F 88 40 04 00 00 C7 04 24 00 00 00 00 E8 03 F5 FF FF 8B 93 34 }
    condition:
        all of them
}

rule Linux_Generic_Threat_9cf10f10 {
    meta:
        id = "GH0CXliXUeZcxM1ALTdXu"
        fingerprint = "v1_sha256_ca4ae64b73fb7013008e8049d17479032d904a3faf5ad0f2ad079971a231a3b8"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d07c9be37dc37f43a54c8249fe887dbc4058708f238ff3d95ed21f874cbb84e8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 84 1E 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 52 C7 05 00 8B 44 24 }
    condition:
        all of them
}

rule Linux_Generic_Threat_75813ab2 {
    meta:
        id = "15NhTlYor23SElwx9aa3nb"
        fingerprint = "v1_sha256_06e5daed278273137e416ef3ee6ac8496b144a9c3ce213ec92881ba61d7db6cb"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5819eb73254fd2a698eb71bd738cf3df7beb65e8fb5e866151e8135865e3fd9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 5B 2B 5D 20 6D 6D 61 70 3A 20 30 78 25 6C 78 20 2E 2E 20 30 78 25 6C 78 }
        $a2 = { 5B 2B 5D 20 70 61 67 65 3A 20 30 78 25 6C 78 }
    condition:
        all of them
}

rule Linux_Generic_Threat_11041685 {
    meta:
        id = "4duDdomcyamh1yAum99xGH"
        fingerprint = "v1_sha256_19f4109e73981424527ece8c375274f97fd3042427b7875071451a8081a9aae7"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "296440107afb1c8c03e5efaf862f2e8cc6b5d2cf979f2c73ccac859d4b78865a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 72 65 73 6F 6C 76 65 64 20 73 79 6D 62 6F 6C 20 25 73 20 74 6F 20 25 70 }
        $a2 = { 73 79 6D 62 6F 6C 20 74 61 62 6C 65 20 6E 6F 74 20 61 76 61 69 6C 61 62 6C 65 2C 20 61 62 6F 72 74 69 6E 67 21 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0d22f19c {
    meta:
        id = "66v0pABmzdE2PQwNBRRnNs"
        fingerprint = "v1_sha256_ee43796b0717717cb012385d5bb3aece433c11780f1a293d280c39411f9fed98"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "da5a204af600e73184455d44aa6e01d82be8b480aa787b28a1df88bb281eb4db"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 55 49 44 20 25 64 2C 20 45 55 49 44 3A 25 64 20 47 49 44 3A 25 64 2C 20 45 47 49 44 3A 25 64 }
        $a2 = { 50 54 52 41 43 45 5F 50 4F 4B 45 55 53 45 52 20 66 61 75 6C 74 }
    condition:
        all of them
}

rule Linux_Generic_Threat_4a46b0e1 {
    meta:
        id = "2JpYGD7AiV2imLAqdvuf8u"
        fingerprint = "v1_sha256_e3f6804f502fad8c893fb4c3c27506b6ef17d7e0d0a01399c6d185bad92e895a"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3ba47ba830ab8deebd9bb906ea45c7df1f7a281277b44d43c588c55c11eba34a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 20 28 76 69 61 20 53 79 73 74 65 6D 2E 6D 61 70 29 }
        $a2 = { 20 5B 2B 5D 20 52 65 73 6F 6C 76 65 64 20 25 73 20 74 6F 20 25 70 25 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0a02156c {
    meta:
        id = "2ytieagK1Vd6WT7rswDmTa"
        fingerprint = "v1_sha256_3ceea812f0252ec703a92482ce7a3ef0aa65bad149df2aa0107e07a45490b8f1"
        version = "1.0"
        date = "2024-02-01"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "f23d4b1fd10e3cdd5499a12f426e72cdf0a098617e6b178401441f249836371e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 72 65 71 75 69 72 65 73 5F 6E 75 6C 6C 5F 70 61 67 65 }
        $a2 = { 67 65 74 5F 65 78 70 6C 6F 69 74 5F 73 74 61 74 65 5F 70 74 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_6d7ec30a {
    meta:
        id = "70mFur92gnJTMD48BFTXt7"
        fingerprint = "v1_sha256_33c705b89a82989c25fc67f50b06aa3a613cae567ec652d86ae64bad4b253c28"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "1cad1ddad84cdd8788478c529ed4a5f25911fb98d0a6241dcf5f32b0cdfc3eb0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 2F 74 6D 70 2F 73 6F 63 6B 73 35 2E 73 68 }
        $a2 = { 63 61 74 20 3C 28 65 63 68 6F 20 27 40 72 65 62 6F 6F 74 20 65 63 68 6F 20 73 6F 63 6B 73 35 5F 62 61 63 6B 63 6F 6E 6E 65 63 74 36 36 36 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 7C 20 28 63 64 20 20 26 26 20 29 27 29 20 3C 28 73 65 64 20 27 2F 73 6F 63 6B 73 35 5F 62 61 63 6B 63 6F 6E 6E 65 63 74 36 36 36 2F 64 27 20 3C 28 63 72 6F 6E 74 61 62 20 2D 6C 20 32 3E 2F 64 65 76 2F 6E 75 6C 6C 29 29 20 7C 20 63 72 6F 6E 74 61 62 20 2D }
    condition:
        all of them
}

rule Linux_Generic_Threat_900ffdd4 {
    meta:
        id = "47UPmvFYnnfXGgRjuCrCPQ"
        fingerprint = "v1_sha256_eb69bfc146b32e790fffdf4588b583335d2006182070b53fec43bb6e4971d779"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a3e1a1f22f6d32931d3f72c35a5ee50092b5492b3874e9e6309d015d82bddc5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 20 48 89 7D E8 89 75 E4 48 83 7D E8 00 74 5C C7 45 FC 00 00 00 00 EB 3D 8B 45 FC 48 98 48 C1 E0 04 48 89 C2 48 8B 45 E8 48 01 D0 48 8B 00 48 85 C0 74 1E 8B 45 FC 48 98 48 C1 E0 04 48 }
    condition:
        all of them
}

rule Linux_Generic_Threat_cb825102 {
    meta:
        id = "4ULWKgyUrldoWgMioj4O9Y"
        fingerprint = "v1_sha256_ac48f32ec82aac6df0697729d14aaee65fba82d91173332cd13c6ccccd63b1be"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "4e24b72b24026e3dfbd65ddab9194bd03d09446f9ff0b3bcec76efbb5c096584"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 5B 2B 5D 20 72 65 73 6F 6C 76 69 6E 67 20 72 65 71 75 69 72 65 64 20 73 79 6D 62 6F 6C 73 2E 2E 2E }
    condition:
        all of them
}

rule Linux_Generic_Threat_3bcc1630 {
    meta:
        id = "3WwRugrh2XKhjS0hTQSGK5"
        fingerprint = "v1_sha256_6f602aac6db46ac3f5b7716a1dac53b5dbd2c583505644bfc617d69be0a2d4de"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "62a6866e924af2e2f5c8c1f5009ce64000acf700bb5351a47c7cfce6a4b2ffeb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 2F 72 6F 6F 74 2F 64 76 72 5F 67 75 69 2F }
        $a2 = { 2F 72 6F 6F 74 2F 64 76 72 5F 61 70 70 2F }
        $a3 = { 73 74 6D 5F 68 69 33 35 31 31 5F 64 76 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_5d5fd28e {
    meta:
        id = "7eo8us5Rqq5tYfevkThHua"
        fingerprint = "v1_sha256_b29ca34b98ee87151496f900fa3558190127957539afac3fd99db2dc51980213"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5b179a117e946ce639e99ff42ab70616ed9f3953ff90b131b4b3063f970fa955"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 2F 75 73 72 2F 62 69 6E 2F 77 64 31 }
        $a2 = { 2F 75 73 72 2F 62 69 6E 2F 63 64 31 }
        $a3 = { 2F 75 73 72 2F 62 69 6E 2F 63 64 74 }
    condition:
        all of them
}

rule Linux_Generic_Threat_b0b891fb {
    meta:
        id = "6FwXCM4ZmzR0P5RCloswlV"
        fingerprint = "v1_sha256_9ec82691a230f3240b1253f99a45cd0baa3238b6fd533004a22a6152b6ac9a12"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d666bc0600075f01d8139f8b09c5f4e4da17fa06a86ebb3fa0dc478562e541ae"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 5F 66 69 6C 65 }
        $a2 = { 2F 64 65 76 2F 75 72 61 6E 64 6F 6D 2F 6D 6E 74 2F 65 78 74 2F 6F 70 74 31 35 32 35 38 37 38 39 30 36 32 35 37 36 32 39 33 39 34 35 33 31 32 35 42 69 64 69 5F 43 6F 6E 74 72 6F 6C 4A 6F 69 6E 5F 43 6F 6E 74 72 6F 6C 4D 65 65 74 65 69 5F 4D 61 79 65 6B 50 61 68 61 77 68 5F 48 6D 6F 6E 67 53 6F 72 61 5F 53 6F 6D 70 65 6E 67 53 79 6C 6F 74 69 5F 4E 61 67 72 69 61 62 69 20 6D 69 73 6D 61 74 63 68 62 61 64 20 66 6C 75 73 68 47 65 6E 62 61 64 20 67 20 73 74 61 74 75 73 62 61 64 20 72 65 63 6F 76 65 72 79 63 61 6E 27 74 20 68 61 70 70 65 6E 63 61 73 36 34 20 66 61 69 6C 65 64 63 68 61 6E 20 72 65 63 65 69 76 65 64 75 6D 70 69 6E 67 20 68 65 61 70 65 6E 64 20 74 72 61 63 65 67 63 }
    condition:
        all of them
}

rule Linux_Generic_Threat_cd9ce063 {
    meta:
        id = "2rjpws8NOyQBpUgdRFgxQo"
        fingerprint = "v1_sha256_ba070c2147028cad4be1c139b16a770c9d9854456d073373a93ed0b213f7b34c"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "485581520dd73429b662b73083d504aa8118e01c5d37c1c08b21a5db0341a19d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 2C 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 2E 61 75 74 6F 74 6D 70 5F 32 36 20 2A 74 6C 73 2E 43 6F 6E 6E 20 7D }
    condition:
        all of them
}

rule Linux_Generic_Threat_b8b076f4 {
    meta:
        id = "nD20EZK8Glb8UY3SzvDyT"
        fingerprint = "v1_sha256_37f3be4cbda4a93136d66e32d7245d4c962a9fe1c98fb0325f42a1d16d6d9415"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "4496e77ff00ad49a32e090750cb10c55e773752f4a50be05e3c7faacc97d2677"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 48 81 EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 44 0F 11 7C 24 2E 44 0F 11 7C 24 2F 44 0F 11 7C 24 3F 44 0F 11 7C 24 4F 44 0F 11 7C 24 5F 48 8B 94 24 C8 00 00 00 48 89 54 }
    condition:
        all of them
}

rule Linux_Generic_Threat_1ac392ca {
    meta:
        id = "612p1M6WIKvRr0m06fsYPn"
        fingerprint = "v1_sha256_6ffa5099c0d18644cd11a0511db542d2f809e4cba974eccca814fedf5a2b0a5b"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "dca2d035b1f7191f7876eb727b13c308f63fe8f899cab643526f9492ec0fa16f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 53 4F 41 50 41 63 74 69 6F 6E 3A 20 75 72 6E 3A 73 63 68 65 6D 61 73 2D 75 70 6E 70 2D 6F 72 67 3A 73 65 72 76 69 63 65 3A 57 41 4E 49 50 43 6F 6E 6E 65 63 74 69 6F 6E 3A 31 23 41 64 64 50 6F 72 74 4D 61 70 70 69 6E 67 }
    condition:
        all of them
}

rule Linux_Generic_Threat_949bf68c {
    meta:
        id = "1TpNXCcEsftnBT1AhnoTBe"
        fingerprint = "v1_sha256_aaae0a8a2827786513891bc8c3e3418823ae3f3291d891e80e82113b929f7513"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cc1b339ff6b33912a8713c192e8743d1207917825b62b6f585ab7c8d6ab4c044"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 55 89 E5 57 56 53 81 EC 58 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 85 B4 FE FF FF 89 95 AC FE FF FF 8D B5 C4 FE FF FF 56 ?? ?? ?? ?? ?? 58 5A 6A 01 56 }
    condition:
        all of them
}

rule Linux_Generic_Threat_bd35454b {
    meta:
        id = "3FUuFdxWZLBMlZzNn1T9i1"
        fingerprint = "v1_sha256_d3619cdb002b4ac7167716234058f949623c42a64614f5eb7956866b68fff5e4"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cd729507d2e17aea23a56a56e0c593214dbda4197e8a353abe4ed0c5fbc4799c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 5F 66 69 6C 65 }
        $a2 = { 57 68 61 74 20 67 75 61 72 61 6E 74 65 65 73 3F }
    condition:
        all of them
}

rule Linux_Generic_Threat_1e047045 {
    meta:
        id = "2mGKx6PvtCQ5vJmnu3fax1"
        fingerprint = "v1_sha256_0d28df53e030664e7225f1170888b51e94e64833537c5add3e10cfdb4f029a3a"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2c49772d89bcc4ad4ed0cc130f91ed0ce1e625262762a4e9279058f36f4f5841"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 18 48 89 FB 48 89 F5 64 48 8B 04 25 28 00 00 00 48 89 44 24 08 31 C0 48 8B 47 08 48 89 C2 48 C1 EA 18 88 14 24 48 89 C2 48 C1 EA 10 88 54 24 01 48 89 C2 48 C1 EA 08 88 54 24 02 88 44 }
    condition:
        all of them
}

rule Linux_Generic_Threat_1973391f {
    meta:
        id = "zenzOae5i29XSAUUMVJSQ"
        fingerprint = "v1_sha256_632a43b68e498f463ff5dfa78212646b8bd108ea47ff11164c8c1a69e830c1ac"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "7bd76010f18061aeaf612ad96d7c03341519d85f6a1683fc4b2c74ea0508fe1f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 70 69 63 6B 75 70 20 2D 6C 20 2D 74 20 66 69 66 6F 20 2D 75 }
        $a2 = { 5B 2D 5D 20 43 6F 6E 6E 65 63 74 20 66 61 69 6C 65 64 2E }
    condition:
        all of them
}

rule Linux_Generic_Threat_66d00a84 {
    meta:
        id = "37ozKoYmtDQzfG43sB4tOt"
        fingerprint = "v1_sha256_a1d60619d72b3309bfaaf8b4085dd5ed90142ff3e9ebfe80fcd7beba5f14a62e"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "464e144bcbb54fc34262b4d81143f4e69e350fb526c803ebea1fdcfc8e57bf33"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 48 81 EC 10 04 00 00 4C 89 E7 49 8D 8C 24 FF 03 00 00 49 89 E0 48 89 E0 8A 17 84 D2 74 14 80 7F 01 00 88 10 74 05 48 FF C0 EB 07 88 58 01 48 83 C0 02 48 FF C7 48 39 F9 75 DE 4C 39 C0 74 06 C6 }
    condition:
        all of them
}

rule Linux_Generic_Threat_d2dca9e7 {
    meta:
        id = "2ilMd09D0yjj7IlFYUMmlh"
        fingerprint = "v1_sha256_175b9a80314cf280b995a012f13e65bd4ce7e27faebf02ae5abe978dbd14447c"
        version = "1.0"
        date = "2024-05-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "9b10bb3773011c4da44bf3a0f05b83079e4ad30f0b1eb2636a6025b927e03c7f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { D0 4D E2 00 50 A0 E1 06 60 8F E0 08 00 00 0A 10 20 90 E5 18 30 90 E5 03 00 52 E1 01 40 D2 34 10 20 80 35 1F 00 00 3A 3B 01 00 EB 00 40 A0 E1 1C 00 00 EA 80 30 9F E5 38 40 80 E2 04 20 A0 E1 03 }
    condition:
        all of them
}

rule Linux_Generic_Threat_1f5d056b {
    meta:
        id = "4DvI8widWFSKI8oqu2XX8E"
        fingerprint = "v1_sha256_8ad23b593880dc1bebc95c92d0efc3a90e6b1e143c350e30b1a4258502ce7fc7"
        version = "1.0"
        date = "2024-05-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "99d982701b156fe3523b359498c2d03899ea9805d6349416c9702b1067293471"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 30 31 32 33 34 35 36 37 38 }
        $a2 = { 47 45 54 20 2F 63 6F 6E 66 69 67 20 48 54 54 50 2F 31 2E 30 }
    condition:
        all of them
}

rule Linux_Generic_Threat_d94e1020 {
    meta:
        id = "32cL07IBfpW9saWMpXw0mI"
        fingerprint = "v1_sha256_e4b4e588588080c66076aec02f56b4764a5f72059922db9651461c0287fe0351"
        version = "1.0"
        date = "2024-05-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "96a2bfbb55250b784e94b1006391cc51e4adecbdde1fe450eab53353186f6ff0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { D0 4D E2 0C C0 9D E5 0C 30 4C E2 02 00 53 E3 14 30 8D E2 00 30 8D E5 10 30 9D E5 0C 10 A0 E1 03 20 A0 E1 01 00 00 8A 0F 00 00 EB 0A 00 00 EA 03 20 A0 E1 0C 10 A0 E1 37 00 90 EF 01 0A 70 E3 00 }
    condition:
        all of them
}

rule Linux_Generic_Threat_aa0c23d5 {
    meta:
        id = "5DLp34PevhJXCJBI8WwO8K"
        fingerprint = "v1_sha256_092f0ece2dfca3e02493c00afffe48ca4feccf56ab6f22d952a7ba5f115f3765"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "8314290b81b827e1a1d157c41916a41a1c033e4f74876acc6806ed79ebbcc13d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F }
        $a2 = { 77 66 6F 66 60 6C 6E 62 67 6E 6A 6D }
        $a3 = { 62 67 6E 6A 6D 77 66 6F 66 60 6C 6E }
    condition:
        all of them
}

rule Linux_Generic_Threat_8299c877 {
    meta:
        id = "3STMfwclJCjqYUCMjZRrQ7"
        fingerprint = "v1_sha256_3e0653a02517faa3037fc5f3f01f6fb11164fecafc6eca457a122ef2d1a99010"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "60c486049ec82b4fa2e0a53293ae6476216b76e2c23238ef1c723ac0a2ae070c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { D0 4D E2 0D 10 A0 E1 07 00 A0 E3 1E 00 00 EB 00 00 50 E3 00 00 9D A5 01 0C A0 B3 0C D0 8D E2 04 E0 9D E4 1E FF 2F E1 04 70 2D E5 CA 70 A0 E3 00 00 00 EF 80 00 BD E8 1E FF 2F E1 04 70 2D E5 C9 }
    condition:
        all of them
}

rule Linux_Generic_Threat_81aa5579 {
    meta:
        id = "5oekYDpLFOH39SSHflvWCR"
        fingerprint = "v1_sha256_c94d590daf61217335a72f3e1bc24b09084cf0a5a174c013c5aa97c01707c2bc"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "6be0e2c98ba5255b76c31f689432a9de83a0d76a898c28dbed0ba11354fec6c2"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { D0 4D E2 07 00 8D E8 03 10 A0 E3 0D 20 A0 E1 08 00 9F E5 84 00 00 EB 0C D0 8D E2 00 80 BD E8 66 00 90 00 01 C0 A0 E1 00 10 A0 E1 08 00 9F E5 02 30 A0 E1 0C 20 A0 E1 7B 00 00 EA 04 00 90 00 01 }
    condition:
        all of them
}

rule Linux_Generic_Threat_f2452362 {
    meta:
        id = "3Jt28SEj7W5xsz4wv0LjjU"
        fingerprint = "v1_sha256_95d51077cb7c0f4b089a2e2ee8fcbab204264ade7ddd64fc1ee0176183dc84e0"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5ff46c27b5823e55f25c9567d687529a24a0d52dea5bc2423b36345782e6b8f6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 6F 72 69 67 69 6E 61 6C 5F 72 65 61 64 64 69 72 }
        $a2 = { 45 72 72 6F 72 20 69 6E 20 64 6C 73 79 6D 3A 20 25 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_da28eb8b {
    meta:
        id = "77DKKrNCWZwxDltTzy4ZM8"
        fingerprint = "v1_sha256_8b0892d0dd8a012a1f9cd87a0ad3321ae751dd17a96205c12e6648946cf2afe2"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "b3b4fcd19d71814d3b4899528ee9c3c2188e4a7a4d8ddb88859b1a6868e8433f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 4A 66 67 67 6C 6A 7D 60 66 67 33 29 62 6C 6C 79 24 68 65 60 }
        $a2 = { 48 6A 6A 6C 79 7D 33 29 7D 6C 71 7D 26 61 7D 64 65 25 68 79 79 65 60 6A 68 7D 60 66 67 26 71 61 7D 64 65 22 71 64 65 25 68 79 79 65 60 6A 68 7D 60 66 67 26 71 64 65 32 78 34 39 27 30 25 60 64 68 6E 6C 26 7E 6C 6B 79 25 23 26 23 32 78 34 39 27 31 }
    condition:
        all of them
}

rule Linux_Generic_Threat_a40aaa96 {
    meta:
        id = "56fzHxwXZQduOSX73AaCaU"
        fingerprint = "v1_sha256_ab05cbf494b3b78083fd3e71703effed797d803b0203f8a413eb69b746656b1d"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "6f965252141084524f85d94169b13938721bce24cc986bf870473566b7cfd81b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 6D 61 69 6E 2E 55 69 6E 74 33 32 6E }
        $a2 = { 6D 61 69 6E 2E 47 65 74 72 61 6E 64 }
        $a3 = { 6D 61 69 6E 2E 28 2A 52 4E 47 29 2E 55 69 6E 74 33 32 }
    condition:
        all of them
}

rule Linux_Generic_Threat_e24558e1 {
    meta:
        id = "2bpgJiCxmEC1T0A8frFoTx"
        fingerprint = "v1_sha256_f1f33c719a4b41968c137ed43aa0591f97b4558d4dd9bd160df519dfbbc49205"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "9f483ddd8971cad4b25bb36a5a0cfb95c35a12c7d5cb9124ef0cfd020da63e99"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 77 66 6F 66 60 6C 6E 62 67 6E 6A 6D }
        $a2 = { 62 67 6E 6A 6D 77 66 6F 66 60 6C 6E }
        $a3 = { 77 62 59 79 43 31 30 37 3A 36 3B 36 3A }
    condition:
        all of them
}

rule Linux_Generic_Threat_ace836f1 {
    meta:
        id = "2FZBiPh5hgFsZtdak2t3bq"
        fingerprint = "v1_sha256_c80af9d6f3e4d92cfa53429abbda944069d335fc89421a89e04089d236f5dddf"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "116aaba80e2f303206d0ba84c8c58a4e3e34b70a8ca2717fa9cf1aa414d5ffcc"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 4E 54 4C 4D 53 53 50 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 73 25 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_e9aef030 {
    meta:
        id = "3FR0idUthfa9pudfoPQ0uY"
        fingerprint = "v1_sha256_1d458e147d6667e2e0740d6d26fee05ac02f49e9eba30002852e723308b1b462"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5ab72be12cca8275d95a90188a1584d67f95d43a7903987e734002983b5a3925"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { D0 4D E2 00 50 A0 E1 0A 00 00 0A 38 40 80 E2 28 31 9F E5 10 00 8D E2 24 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 40 00 13 E2 05 }
    condition:
        all of them
}

rule Linux_Generic_Threat_a3c5f3bd {
    meta:
        id = "71xO5Qb56VZwx8LWHwwlpg"
        fingerprint = "v1_sha256_41e66d1f47e7197662aa661ef49ee1f3191fee07a49538dd631ce9cc6fdd56be"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "8c093bcf3d83545ec442519637c956d2af62193ea6fd2769925cacda54e672b6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 66 68 5F 72 65 6D 6F 76 65 5F 68 6F 6F 6B }
        $a2 = { 66 68 5F 66 74 72 61 63 65 5F 74 68 75 6E 6B }
        $a3 = { 66 68 5F 69 6E 73 74 61 6C 6C 5F 68 6F 6F 6B }
    condition:
        all of them
}

rule Linux_Generic_Threat_3fa2df51 {
    meta:
        id = "6I6vrztA04Ram6Ry70zsnY"
        fingerprint = "v1_sha256_f43b659dd093a635d9723b2443366763132217aaf28c582ed43f180725f92f19"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "89ec224db6b63936e8bc772415d785ef063bfd9343319892e832034696ff6f15"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 5B 6B 77 6F 72 6B 65 72 2F 30 3A 32 5D }
        $a2 = { 2F 74 6D 70 2F 6C 6F 67 5F 64 65 2E 6C 6F 67 }
    condition:
        all of them
}

rule Linux_Generic_Threat_be02b1c9 {
    meta:
        id = "3NqOSLRdqjLB2FhY8VHrpD"
        fingerprint = "v1_sha256_a278c3a8033139d84c99a53901526895b154b5ef363fbeed47095889a5fb8d31"
        version = "1.0"
        date = "2024-05-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "ef6d47ed26f9ac96836f112f1085656cf73fc445c8bacdb737b8be34d8e3bcd2"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 18 48 89 FB 48 89 F5 48 8B 47 08 48 89 C2 48 C1 EA 18 88 14 24 48 89 C2 48 C1 EA 10 88 54 24 01 48 89 C2 48 C1 EA 08 88 54 24 02 88 44 24 03 48 8B 07 48 89 C2 48 C1 EA 18 88 54 24 04 }
    condition:
        all of them
}

