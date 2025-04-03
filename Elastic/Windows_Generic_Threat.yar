rule Windows_Generic_Threat_bc6ae28d {
    meta:
        id = "6HxfxqBDLTXROfyrxoeDnr"
        fingerprint = "v1_sha256_0ca5ec945858a5238eac048520dea4597f706ad2c96be322d341c84c4ddbce33"
        version = "1.0"
        date = "2023-12-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ce00873eb423c0259c18157a07bf7fd9b07333e528a5b9d48be79194310c9d97"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C 24 E8 DB FC FF FF 85 C0 74 05 8B 45 F0 C9 C3 83 C8 FF C9 C3 55 8B EC 83 EC 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C }
    condition:
        all of them
}

rule Windows_Generic_Threat_ce98c4bc {
    meta:
        id = "ssJHD56UY1c0V8GY4WmRY"
        fingerprint = "v1_sha256_74914f41c03cb2dcb1dc3175cc76574a0d40b66a1a3854af8f50c9858704b66b"
        version = "1.0"
        date = "2023-12-17"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "950e8a29f516ef3cf1a81501e97fbbbedb289ad9fb93352edb563f749378da35"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 4D 65 73 73 61 67 65 50 61 63 6B 4C 69 62 2E 4D 65 73 73 61 67 65 50 61 63 6B }
        $a2 = { 43 6C 69 65 6E 74 2E 41 6C 67 6F 72 69 74 68 6D }
    condition:
        all of them
}

rule Windows_Generic_Threat_0cc1481e {
    meta:
        id = "aqCL2Lr73zwrEHrf3urSi"
        fingerprint = "v1_sha256_1a094cf337cb85aa4b7d1d2025571ab0661a7be1fd03d53d8c7370a90385f38c"
        version = "1.0"
        date = "2023-12-17"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6ec7781e472a6827c1406a53ed4699407659bd57c33dd4ab51cabfe8ece6f23f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 A8 53 56 57 8B FA 8B D8 8B 43 28 3B 78 10 0F 84 B4 00 00 00 8B F0 85 FF 75 15 83 7E 04 01 75 0F 8B 46 10 E8 03 A7 FF FF 33 C0 89 46 10 EB 7C 8B C3 E8 B5 F3 FF FF 8B C3 E8 BE F3 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2507c37c {
    meta:
        id = "39FTmYuErpFxbDDFux7hyI"
        fingerprint = "v1_sha256_8c5ea1290260993ea5140baa4645f3fd0ebb4d43fce0e9a25f8e8948e683aec1"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "04296258f054a958f0fd013b3c6a3435280b28e9a27541463e6fc9afe30363cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 45 14 56 57 33 FF 3B C7 74 47 39 7D 08 75 1B E8 B2 2B 00 00 6A 16 5E 89 30 57 57 57 57 57 E8 3B 2B 00 00 83 C4 14 8B C6 EB 29 39 7D 10 74 E0 39 45 0C 73 0E E8 8D 2B 00 00 6A 22 59 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e052d248 {
    meta:
        id = "1OcSRye6usdkG00MZwYuQU"
        fingerprint = "v1_sha256_1a16ce6d1c6707560425156e625ad19a82315564b3f03adafbcc3e65b0e98a6d"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ed2bbc0d120665044aacb089d8c99d7c946b54d1b08a078aebbb3b91f593da6e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 64 A1 00 00 00 00 6A FF 68 4F 5A 54 00 50 64 89 25 00 00 00 00 6A 02 68 24 D0 58 00 E8 FF 65 10 00 C7 45 FC FF FF FF FF 68 10 52 55 00 E8 F7 72 10 00 8B 4D F4 83 C4 0C 64 89 0D 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2bb7fbe3 {
    meta:
        id = "3ucX6HvKBHKj4wvQOKW87A"
        fingerprint = "v1_sha256_36e1ab766e09e8d06b9179f67a1cb842ba257f140610964a941fb462ed3e803c"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "65cc8704c0e431589d196eadb0ac8a19151631c8d4ab7375d7cb18f7b763ba7b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 14 68 B6 32 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 30 53 56 57 89 65 EC C7 45 F0 C0 15 40 00 33 F6 89 75 F4 89 75 F8 89 75 E0 89 75 DC 89 75 D8 6A 01 FF 15 AC 10 }
    condition:
        all of them
}

rule Windows_Generic_Threat_994f2330 {
    meta:
        id = "68WLPalWO2uwbDD4r0gYbY"
        fingerprint = "v1_sha256_ace99deae7f5faa22f273ec4fe45ef07f03acd1ae4d9c0f18687ef6cf5b560c2"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0a30cb09c480a2659b6f989ac9fe1bfba1802ae3aad98fa5db7cdd146fee3916"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 0C 8B 55 08 85 D2 0F 84 C7 00 00 00 8B 42 3C 83 7C 10 74 10 8D 44 10 18 0F 82 B5 00 00 00 83 78 64 00 0F 84 AB 00 00 00 8B 4D 0C 8B 40 60 C1 E9 10 03 C2 66 85 C9 75 14 0F B7 4D }
    condition:
        all of them
}

rule Windows_Generic_Threat_bf7aae24 {
    meta:
        id = "5huvON9u3bAV7gIi2cy1di"
        fingerprint = "v1_sha256_b6dfa6f4c46bddd643f2f89f6275404c19fd4ed1bbae561029fffa884e99e167"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6dfc63894f15fc137e27516f2d2a56514c51f25b41b00583123142cf50645e4e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 33 F6 44 8B EE 48 89 74 24 20 8B EE 48 89 B4 24 A8 00 00 00 44 8B F6 48 89 74 24 28 44 8B E6 E8 BF FF FF FF 4C 8B F8 8D 5E 01 B8 4D 5A 00 00 66 41 39 07 75 1B 49 63 57 3C 48 8D 4A }
    condition:
        all of them
}

rule Windows_Generic_Threat_d542e5a5 {
    meta:
        id = "6KAsjXRLcsqMh6TNdTFFmG"
        fingerprint = "v1_sha256_3c16c02d4fc6e019f0ab0ff4daad61f59275afd8fb3ee263b1b59876233a686e"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3fc4ae7115e0bfa3fc6b75dcff867e7bf9ade9c7f558f31916359d37d001901b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 56 FF 75 08 8B F1 E8 B6 FF FF FF C7 06 AC 67 41 00 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 FF 75 08 8B F1 E8 99 FF FF FF C7 06 B8 67 41 00 8B C6 5E 5D C2 04 00 B8 EF 5B 40 00 A3 E8 5A }
    condition:
        all of them
}

rule Windows_Generic_Threat_8d10790b {
    meta:
        id = "4RxjBXlg7waR95m0brypif"
        fingerprint = "v1_sha256_84c017abbce1c8702efbe8657e5a857ae222721b0db2260dc814652f4528df26"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "911535923a5451c10239e20e7130d371e8ee37172e0f14fc8cf224d41f7f4c0f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 81 EC 04 00 00 00 8B 5D 08 8B 1B 83 C3 04 89 5D FC 8B 45 0C 8B 5D FC 89 03 8B E5 5D C2 08 00 55 8B EC 81 EC 0C 00 00 00 C7 45 FC 00 00 00 00 68 00 00 00 00 BB C4 02 00 00 E8 0D 05 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_347f9f54 {
    meta:
        id = "6m4vXW8ABCqoCHIOc924Cx"
        fingerprint = "v1_sha256_63df388393a45ffec68ba01ae6d7707b6d5277e0162ded6e631c1f76ad76b711"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "45a051651ce1edddd33ecef09bb0fbb978adec9044e64f786b13ed81cabf6a3f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 10 FF 75 0C 80 65 FC 00 8D 45 F0 C6 45 F0 43 50 C6 45 F1 6F FF 75 08 C6 45 F2 6E C6 45 F3 6E C6 45 F4 65 C6 45 F5 63 C6 45 F6 74 C6 45 F7 47 C6 45 F8 72 C6 45 F9 6F C6 45 FA 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_20469956 {
    meta:
        id = "4LyKI8cBgeg0hwUgdIX3DH"
        fingerprint = "v1_sha256_da351bec0039a32bb9de1d8623ab3dc26eb752d30a64e613de96f70e1b1c2463"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "a1f2923f68f5963499a64bfd0affe0a729f5e7bd6bcccfb9bed1d62831a93c47"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 E4 F8 83 EC 5C 53 56 33 C0 C7 44 24 18 6B 00 6C 00 57 8D 4C 24 1C C7 44 24 20 69 00 66 00 C7 44 24 24 2E 00 73 00 C7 44 24 28 79 00 73 00 66 89 44 24 2C C7 44 24 0C 6B 00 6C 00 C7 }
    condition:
        all of them
}

rule Windows_Generic_Threat_742e8a70 {
    meta:
        id = "3z55ARuw5xzjwd67XbpVXe"
        fingerprint = "v1_sha256_2925eb8da80ef791b5cf7800a9bf9462203ab6aa743bc69f4fd2343e97eaab7c"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "94f7678be47651aa457256375f3e4d362ae681a9524388c97dc9ed34ba881090"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC E8 96 FF FF FF E8 85 0D 00 00 83 7D 08 00 A3 A4 E9 43 00 74 05 E8 0C 0D 00 00 DB E2 5D C3 8B FF 55 8B EC 83 3D B0 E9 43 00 02 74 05 E8 BA 12 00 00 FF 75 08 E8 07 11 00 00 68 FF 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_79174b5c {
    meta:
        id = "1ed7PFT8xyvQBVc2QVTN2e"
        fingerprint = "v1_sha256_06a2f0613719f1273a6b3f62f248c22b1cab2fe6054904619e3720f3f6c55e2e"
        version = "1.0"
        date = "2023-12-18"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c15118230059e85e7a6b65fe1c0ceee8997a3d4e9f1966c8340017a41e0c254c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 48 56 57 6A 0F 33 C0 59 8D 7D B9 F3 AB 8B 75 0C 6A 38 66 AB 8B 4E 14 AA 8B 46 10 89 4D FC 89 45 F8 59 C1 E8 03 83 E0 3F C6 45 B8 80 3B C1 72 03 6A 78 59 2B C8 8D 45 B8 51 50 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_232b71a9 {
    meta:
        id = "7Hg3LwmIRCmVVeSmX9Pe1p"
        fingerprint = "v1_sha256_c3bef1509c0d0172dbbc7e0e2b5c69e5ec47dc22365d98a914002b53b0f7d918"
        version = "1.0"
        date = "2023-12-20"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1e8b34da2d675af96b34041d4e493e34139fc8779f806dbcf62a6c9c4d9980fe"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 61 61 62 63 64 65 65 66 67 68 69 69 6A 6B 6C 6D 6E 6F 6F 70 71 72 73 74 75 75 76 77 78 79 7A 61 55 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d331d190 {
    meta:
        id = "5Y3gpJSJtwAauTjYGwwlZN"
        fingerprint = "v1_sha256_901601c892d709fa596c44df1fbe7772a9f20576c71666570713bf96727a809b"
        version = "1.0"
        date = "2023-12-20"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6d869d320d977f83aa3f0e7719967c7e54c1bdae9ae3729668d755ee3397a96f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 83 FA 03 74 04 85 D2 75 05 E8 EE 08 00 00 B8 01 00 00 00 48 83 C4 28 C3 CC CC CC CC 56 57 48 83 EC 38 48 89 CE 8B 01 FF C8 83 F8 05 77 12 48 98 48 8D 0D D1 49 00 00 48 63 3C 81 48 }
    condition:
        all of them
}

rule Windows_Generic_Threat_24191082 {
    meta:
        id = "5y4moTPbvrJUVjB1ll6w6Z"
        fingerprint = "v1_sha256_a5ea76032a9c189f923d91cd03deb44bd61868e5ad6081afe63249156cbd8927"
        version = "1.0"
        date = "2023-12-20"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4d20878c16d2b401e76d8e7c288cf8ef5aa3c8d4865f440ee6b44d9f3d0cbf33"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 45 0C 48 F7 D0 23 45 08 5D C3 55 8B EC 51 8B 45 0C 48 23 45 08 74 15 FF 75 0C FF 75 08 E8 DA FF FF FF 59 59 03 45 0C 89 45 FC EB 06 8B 45 08 89 45 FC 8B 45 FC 8B E5 5D C3 55 8B EC }
    condition:
        all of them
}

rule Windows_Generic_Threat_efdb9e81 {
    meta:
        id = "6qLP0AjOiXtEj1cFp3T1Sx"
        fingerprint = "v1_sha256_eae78b07f6c31e3a30ae041a27c67553bb8ea915bc7724583d78832475021955"
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1c3302b14324c9f4e07829f41cd767ec654db18ff330933c6544c46bd19e89dd"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 4D 61 78 69 6D 75 6D 43 68 65 63 6B 42 6F 78 53 69 7A 65 }
        $a2 = { 56 69 73 75 61 6C 50 6C 75 73 2E 4E 61 74 69 76 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_34622a35 {
    meta:
        id = "7NzQpzX2wE70R3B4U6QVGl"
        fingerprint = "v1_sha256_2b49bd5d3a18307a46f44d9dfeea858ddaa6084f86f96b83b874cee7603e1c11"
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c021c6adca0ddf38563a13066a652e4d97726175983854674b8dae2f6e59c83f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 81 EC 88 00 00 00 C7 45 FC 00 00 00 00 C7 45 F8 00 00 00 00 68 4C 00 00 00 E8 A3 42 00 00 83 C4 04 89 45 F4 8B D8 8B F8 33 C0 B9 13 00 00 00 F3 AB 83 C3 38 53 68 10 00 00 00 E8 82 42 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0ff403df {
    meta:
        id = "7iOe4GKoSsEeJAZsSiDNxI"
        fingerprint = "v1_sha256_38bdd9b6f61ab4bb13abc7af94e92151928df95ade061756611218104e7245fd"
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b3119dc4cea05bef51d1f373b87d69bcff514f6575d4c92da4b1c557f8d8db8f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 81 EC 00 02 00 00 56 8B F1 57 C6 85 00 FF 63 C7 06 0C 22 41 00 0C 66 69 B6 66 01 7C 06 02 77 03 96 66 69 B6 7B 14 04 F2 05 6B 06 69 96 66 69 6F 07 C5 08 30 66 69 96 66 09 01 0A 67 0B }
    condition:
        all of them
}

rule Windows_Generic_Threat_b1f6f662 {
    meta:
        id = "2JJWp2vBYELdC3ZWKezrlV"
        fingerprint = "v1_sha256_e52ff1eaee00334e1a07367bf88f3907bb0b13035717683d9d98371b92bc45c0"
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1b7eaef3cf1bb8021a00df092c829932cccac333990db1c5dac6558a5d906400"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
        $a2 = { 73 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
        $a3 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 31 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2c80562d {
    meta:
        id = "BfuqMRTeo2wijcF0loS0D"
        fingerprint = "v1_sha256_07487ae646ac81b94f940c8d3493dbee023bce687297465fe09375f40dff0fb2"
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ee8decf1e8e5a927e3a6c10e88093bb4b7708c3fd542d98d43f1a882c6b0198e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 50 6F 6C 79 6D 6F 64 58 54 2E 65 78 65 }
        $a2 = { 50 6F 6C 79 6D 6F 64 58 54 20 76 31 2E 33 }
        $a3 = { 50 6F 6C 79 6D 6F 64 20 49 6E 63 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_e96f9e97 {
    meta:
        id = "7XLyqoXefhZrJaQheZneve"
        fingerprint = "v1_sha256_1dcf81b8982425ff74107b899e85e2432f0464554e923f85a7555cda65293b54"
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bfbab69e9fc517bc46ae88afd0603a498a4c77409e83466d05db2797234ea7fc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 7A 47 4D 5E 5A 4D 5D 4B 7D 6D 4A 41 57 4B 54 49 5F 4C 67 6D 54 52 5B 51 46 43 6F 71 40 46 45 53 67 7C 5D 6F }
    condition:
        all of them
}

rule Windows_Generic_Threat_005fd471 {
    meta:
        id = "4Wruw94fKDvqUIOXB0moA2"
        fingerprint = "v1_sha256_10493253a6b2ce3141ee980e0607bdbba72580bb4a076f2f4636e9665ffc6db8"
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "502814ed565a923da15626d46fde8cc7fd422790e32b3cad973ed8ec8602b228"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5F 3F 44 4B 4B 66 25 37 2A 5E 70 42 70 }
        $a2 = { 71 5A 3E 7D 6F 5D 6E 2D 74 48 5E 55 55 22 3C }
        $a3 = { 3E 2D 21 47 45 6A 3C 33 23 47 5B 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_54b0ec47 {
    meta:
        id = "5a3A9mcHUfxTBBrngRksbX"
        fingerprint = "v1_sha256_e3d74162a8874fe05042fec98d25b8db50e7f537566fd9f4e40f92bfe868259a"
        version = "1.0"
        date = "2024-01-03"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9c14203069ff6003e7f408bed71e75394de7a6c1451266c59c5639360bf5718c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 2D 2D 2D 2D 3D 5F 25 73 5F 25 2E 33 75 5F 25 2E 34 75 5F 25 2E 38 58 2E 25 2E 38 58 }
        $a2 = { 25 73 2C 20 25 75 20 25 73 20 25 75 20 25 2E 32 75 3A 25 2E 32 75 3A 25 2E 32 75 20 25 63 25 2E 32 75 25 2E 32 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_acf6222b {
    meta:
        id = "A8KkuwNsYSiqDVPuYzLHq"
        fingerprint = "v1_sha256_a284b6c163dbc022bd36f19fbc1d7ff70143bee566328ad23e7b8b79abd39e91"
        version = "1.0"
        date = "2024-01-03"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ce0def96be08193ab96817ce1279e8406746a76cfcf4bf44e394920d7acbcaa6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 7D 10 00 75 04 33 C0 5D C3 8B 4D 08 8B 55 0C FF 4D 10 74 0E 8A 01 84 C0 74 08 3A 02 75 04 41 42 EB ED 0F B6 01 0F B6 0A 2B C1 5D C3 55 8B EC 83 EC 24 56 57 8B 7D 08 33 F6 89 75 F8 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5e718a0c {
    meta:
        id = "7ZJxOIsMEeBAbP85cDnjCy"
        fingerprint = "v1_sha256_45068afeda7abae0fe922a21f8f768b6c74a6e0f8e9e8b1f68c3ddf92940bf9a"
        version = "1.0"
        date = "2024-01-03"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "430b9369b779208bd3976bd2adc3e63d3f71e5edfea30490e6e93040c1b3bac6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 44 3A 28 41 3B 3B 30 78 30 30 31 46 30 30 30 33 3B 3B 3B 42 41 29 28 41 3B 3B 30 78 30 30 31 30 30 30 30 33 3B 3B 3B 41 55 29 }
    condition:
        all of them
}

rule Windows_Generic_Threat_fac6d993 {
    meta:
        id = "58dOwHZnzKh9gIGYT8itYq"
        fingerprint = "v1_sha256_3486793324dbe43c908432e1956bbbdb870beb4641da46b3786581fd3e78811a"
        version = "1.0"
        date = "2024-01-03"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f3e7c88e72cf0c1f4cbee588972fc1434065f7cc9bd95d52379bade1b8520278"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 E4 F8 81 EC 4C 04 00 00 53 8B D9 8B 4D 2C 33 C0 89 01 8B 4D 30 56 0F B6 B3 85 00 00 00 89 01 8B 4D 34 57 0F B6 BB 84 00 00 00 89 01 8B 4D 38 89 54 24 10 89 01 8D 44 24 48 50 FF 15 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e7eaa4ca {
    meta:
        id = "3y6tGWhwV5vH6V4jbymaRQ"
        fingerprint = "v1_sha256_600da0c88dc0606e05f60ecd3b9a90469eef8ac7a702ef800c833f7fd17eb13e"
        version = "1.0"
        date = "2024-01-04"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { C8 F7 C6 A8 13 F7 01 E9 2C 99 08 00 4C 03 D1 E9 }
    condition:
        all of them
}

rule Windows_Generic_Threat_97703189 {
    meta:
        id = "4Aibnhq5mzWhPYKnzIzNIK"
        fingerprint = "v1_sha256_318bc82d49e9a3467ec0e0086aaf1092d2aa7c589b5f16ce6fbb3778eda7ef0b"
        version = "1.0"
        date = "2024-01-04"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "968ba3112c54f3437b9abb6137f633d919d75137d790af074df40a346891cfb5"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 5D E9 2A 1C 00 00 8B FF 55 8B EC 8B 45 08 56 8B F1 C6 46 0C 00 85 C0 75 63 E8 6F 29 00 00 89 46 08 8B 48 6C 89 0E 8B 48 68 89 4E 04 8B 0E 3B 0D 98 06 49 00 74 12 8B 0D B4 05 49 00 85 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ca0686e1 {
    meta:
        id = "bnpVH2CVXIzo5WlnWyxU4"
        fingerprint = "v1_sha256_12b2ff66d1be6e2d27f24489b389b5c84660921e8de41653b2b425077cc87669"
        version = "1.0"
        date = "2024-01-05"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "15c7ce1bc55549efc86dea74a90f42fb4665fe15b14f760037897c772159a5b5"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 8B 5D 08 56 57 8B F9 8B 77 10 8B C6 2B C3 89 75 FC 3B 45 0C 72 03 8B 45 0C 83 7F 14 10 72 02 8B 0F 8D 14 19 2B F0 8B CE 03 C2 2B CB 41 51 50 52 E8 62 1A 00 00 83 C4 0C 8B CF 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_97c1a260 {
    meta:
        id = "2dRurRFlhhZ25fXECsIDGl"
        fingerprint = "v1_sha256_5bd84cbdd4ba699c9e9d87e684071342b23138538bd83ffea8c524fcee26a59b"
        version = "1.0"
        date = "2024-01-07"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2cc85ebb1ef07948b1ddf1a793809b76ee61d78c07b8bf6e702c9b17346a20f1"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 56 57 E8 14 31 00 00 8B F0 85 F6 0F 84 39 01 00 00 8B 16 33 DB 8B CA 8D 82 90 00 00 00 3B D0 74 0E 8B 7D 08 39 39 74 09 83 C1 0C 3B C8 75 F5 8B CB 85 C9 0F 84 11 01 00 00 8B 79 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a440f624 {
    meta:
        id = "6NtaPdlI3zQRX3R0HoVPdU"
        fingerprint = "v1_sha256_23c759a0db5698b28a69232077a6b714f71e8eaa069d2f02a7d3efc48b178a2b"
        version = "1.0"
        date = "2024-01-07"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3564fec3d47dfafc7e9c662654865aed74aedeac7371af8a77e573ea92cbd072"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 73 6B 20 3D 20 25 64 }
        $a2 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 4C 65 6E 20 3D 20 25 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b577c086 {
    meta:
        id = "13VHV5nh8vJHoeiN0I6CFV"
        fingerprint = "v1_sha256_a7684340171415ee01e855706192cdffcccd6c82362707229b2c1d096f87dfa8"
        version = "1.0"
        date = "2024-01-07"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "27dd61d4d9997738e63e813f8b8ea9d5cf1291eb02d20d1a2ad75ac8aa99459c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 24 83 7D 08 00 75 0A B8 9A FF FF FF E9 65 02 00 00 8B 45 08 89 45 FC 8B 4D FC 83 79 18 00 75 0A B8 9A FF FF FF E9 4C 02 00 00 8B 55 FC 83 7A 7C 00 74 0C 8B 45 08 50 E8 5F 06 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_62e1f5fc {
    meta:
        id = "5reiNjGPmUS1qhvsgKjO8y"
        fingerprint = "v1_sha256_76e21746ee396f13073b3db1e876246f01cef547d312691dff3dc895ea3a2b82"
        version = "1.0"
        date = "2024-01-07"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4a692e244a389af0339de8c2d429b541d6d763afb0a2b1bb20bee879330f2f42"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 43 6C 69 65 6E 74 2E 48 61 6E 64 6C 65 5F 50 61 63 6B 65 74 }
        $a2 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
        $a3 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }
    condition:
        all of them
}

rule Windows_Generic_Threat_55d6a1ab {
    meta:
        id = "1ajQVV1qTwLUuxZtxJLBuT"
        fingerprint = "v1_sha256_4f3a0b2e45ae4e6a00f137798b700a0925fa6eb19ea6b871d7eeb565548888ba"
        version = "1.0"
        date = "2024-01-07"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1ca6ed610479b5aaaf193a2afed8f2ca1e32c0c5550a195d88f689caab60c6fb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 51 51 31 33 37 32 33 39 32 34 38 20 }
        $a2 = { 74 65 6E 63 65 6E 74 3A 2F 2F 6D 65 73 73 61 67 65 2F 3F 75 69 6E 3D 31 33 37 32 33 39 32 34 38 26 53 69 74 65 3D 63 66 }
    condition:
        all of them
}

rule Windows_Generic_Threat_f7d3cdfd {
    meta:
        id = "1C8Mc9bw7GYzdX8MfL86D8"
        fingerprint = "v1_sha256_23e1008f222eb94a4bd34372834924377e813dc76efa8544b0dcbe7d3e3addde"
        version = "1.0"
        date = "2024-01-07"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f9df83d0b0e06884cdb4a02cd2091ee1fadeabb2ea16ca34cbfef4129ede251f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 51 56 57 E8 A3 D0 FF FF 83 78 68 00 74 21 FF 75 24 FF 75 20 FF 75 18 FF 75 14 FF 75 10 FF 75 0C FF 75 08 E8 E5 8C FF FF 83 C4 1C 85 C0 75 73 8B 7D 1C 8D 45 F8 50 8D 45 FC 50 57 FF }
    condition:
        all of them
}

rule Windows_Generic_Threat_0350ed31 {
    meta:
        id = "4DjoNKvWIDenj1ihxcvRdO"
        fingerprint = "v1_sha256_149dd26466f47b2e7f514bdcc9822470334490da2898840f35fe6b537ce104f6"
        version = "1.0"
        date = "2024-01-07"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "008f9352765d1b3360726363e3e179b527a566bc59acecea06bd16eb16b66c5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 35 6A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 6A 29 59 7A 3F }
    condition:
        all of them
}

rule Windows_Generic_Threat_a1cef0cd {
    meta:
        id = "5krVhKYlp8ObnwwUnxRLrG"
        fingerprint = "v1_sha256_2772906e3a8a088e7c6ea1370af5e5bbe2cbae4f49de9b939524e317be8ddde4"
        version = "1.0"
        date = "2024-01-08"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "71f519c6bd598e17e1298d247a4ad37b78685ca6fd423d560d397d34d16b7db8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 8B DA 89 45 FC 8B 45 FC E8 76 00 00 00 33 C0 55 68 F0 A0 41 00 64 FF 30 64 89 20 8B 45 FC 80 78 20 01 74 10 8B 45 FC 8B 40 04 8B D3 E8 CE FC FF FF 40 75 0F 8B 45 FC 8B 40 04 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_e5f4703f {
    meta:
        id = "8zNoQ6kRoNuZlSTKagu3M"
        fingerprint = "v1_sha256_f81476d5e5a9bcb42b32d6ec3d4b620165f2878c50691ecf59ef6f34b6ad9d1b"
        version = "1.0"
        date = "2024-01-09"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "362bda1fad3fefce7d173617909d3c1a0a8e234e22caf3215ee7c6cef6b2743b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 E4 F8 83 EC 08 83 79 14 08 56 57 8B F1 72 02 8B 31 8B 41 10 8B CE 8D 3C 46 8B D7 E8 AC FA FF FF 8B 75 08 2B F8 D1 FF 0F 57 C0 57 50 0F 11 06 8B CE C7 46 10 00 00 00 00 C7 46 14 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_8b790aba {
    meta:
        id = "63L4h0yaaTD4IraHKFvkpq"
        fingerprint = "v1_sha256_8a0b2af3d0c95466ca138dfcc3d6f6a702ec92f5cd4f791b1200c79ffd973840"
        version = "1.0"
        date = "2024-01-09"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ec98bfff01d384bdff6bbbc5e17620b31fa57c662516157fd476ef587b8d239e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 7A 66 62 50 4A 64 73 72 78 77 7B 7B 79 55 36 46 42 50 4A 3F 20 2E 6E 3E 36 65 73 7A }
        $a2 = { 50 36 7B 77 64 71 79 64 46 4A 73 64 79 62 45 7A 77 63 62 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_76a7579f {
    meta:
        id = "7FSnG2Q97SW2qP7SmbT9jS"
        fingerprint = "v1_sha256_08ed2d318e7154195911aaf3705626307b48a54aa195eaa054ec53766d3e198d"
        version = "1.0"
        date = "2024-01-09"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "76c73934bcff7e4ee08b068d1e02b8f5c22161262d127de2b4ac2e81d09d84f6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 55 10 8B 45 08 8B C8 85 D2 74 09 C6 01 00 41 83 EA 01 75 F7 5D C3 55 8B EC 64 A1 30 00 00 00 83 EC 18 8B 40 0C 53 56 57 8B 78 0C E9 A7 00 00 00 8B 47 30 33 F6 8B 5F 2C 8B 3F 89 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_3f060b9c {
    meta:
        id = "3bufDpN4vgTroJZwRueh27"
        fingerprint = "v1_sha256_193583f63f22452f96c8372fdc9ef04e2a684f847564a7fe75145ea30d426901"
        version = "1.0"
        date = "2024-01-10"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "32e7a40b13ddbf9fc73bd12c234336b1ae11e2f39476de99ebacd7bbfd22fba0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 51 53 56 8B F1 E8 4B BE FF FF 8D 45 FC 8B CE 50 FF 75 10 FF 75 0C E8 69 FE FF FF 8B D8 8B CE 53 E8 4B FD FF FF 85 C0 0F 84 C6 00 00 00 8B 46 40 83 F8 02 0F 84 B3 00 00 00 83 F8 05 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dbae6542 {
    meta:
        id = "44a5K3HjLgOZDiJkTR8REb"
        fingerprint = "v1_sha256_673c6b4e6aaa127d45b21d0283437000fbc507a84ecd7a326448869d63759aee"
        version = "1.0"
        date = "2024-01-10"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c73f533f96ed894b9ff717da195083a594673e218ee9a269e360353b9c9a0283"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0F 00 00 04 2D 0A 28 27 00 00 06 28 19 00 00 06 7E 15 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A EE 16 80 0F 00 00 04 14 }
    condition:
        all of them
}

rule Windows_Generic_Threat_808f680e {
    meta:
        id = "YRtqS3REoGaZgdRkkgxkm"
        fingerprint = "v1_sha256_22d91a87c01b401d4a203fbabb93a9b45fd6d8819125c56d9c427449b06d2f84"
        version = "1.0"
        date = "2024-01-10"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "df6955522532e365239b94e9d834ff5eeeb354eec3e3672c48be88725849ac1c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 20 00 00 00 00 FE 01 2A 13 30 02 00 6C 00 00 00 01 00 00 11 20 00 00 00 00 FE 0E 00 00 38 54 00 00 00 00 FE 0C 00 00 20 01 00 00 00 FE 01 39 12 00 00 00 FE 09 01 00 FE 09 02 00 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_073909cf {
    meta:
        id = "aWqU1sTO8Ks8C8XoXMFwo"
        fingerprint = "v1_sha256_5b42a74010549c884ff85a67b9add6b82a8109a953473cc1439581976f8f545e"
        version = "1.0"
        date = "2024-01-10"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "89a6dc518c119b39252889632bd18d9dfdae687f7621310fb14b684d2f85dad8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 F0 53 56 89 55 FC 8B F0 8B 45 FC E8 CF E5 FF FF 33 C0 55 68 F2 39 40 00 64 FF 30 64 89 20 33 DB 68 04 3A 40 00 68 0C 3A 40 00 E8 70 FC FF FF 50 E8 82 FC FF FF 89 45 F8 68 18 3A }
    condition:
        all of them
}

rule Windows_Generic_Threat_820fe9c9 {
    meta:
        id = "1SmxF58z5Bbr6nR1g7ND7O"
        fingerprint = "v1_sha256_81a1359bd5781e1eefb6ae06c6b2ad9e94cc6318c1f81f84c06f0b236b6e84d1"
        version = "1.0"
        date = "2024-01-11"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1102a499b8a863bdbfd978a1d17270990e6b7fe60ce54b9dd17492234aad2f8c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 2E 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 58 30 20 63 68 61 6E 20 73 74 72 69 6E 67 3B 20 58 31 20 62 6F 6F 6C 20 7D }
    condition:
        all of them
}

rule Windows_Generic_Threat_89efd1b4 {
    meta:
        id = "4f630av1nnwBwNgzvWRury"
        fingerprint = "v1_sha256_49a7875fd9c31c5c9b593aed75a28fadb586294422b75c7a8eeba2e8ff254753"
        version = "1.0"
        date = "2024-01-11"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "937c8bc3c89bb9c05b2cb859c4bf0f47020917a309bbadca36236434c8cdc8b9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 81 EC E0 01 00 00 48 89 9C 24 F8 01 00 00 48 83 F9 42 0F 85 03 01 00 00 48 89 84 24 F0 01 00 00 48 89 9C 24 F8 01 00 00 44 0F 11 BC 24 88 01 00 00 44 0F 11 BC 24 90 01 00 00 44 0F 11 BC 24 }
    condition:
        all of them
}

rule Windows_Generic_Threat_61315534 {
    meta:
        id = "4rSKS6VWSxDGUmn0e0PMHT"
        fingerprint = "v1_sha256_0fdfe3bb6ebdaac4324a45dac8680f00684d0030419f26f3f72ed002bf5a2a34"
        version = "1.0"
        date = "2024-01-11"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "819447ca71080f083b1061ed6e333bd9ef816abd5b0dd0b5e6a58511ab1ce8b9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 51 8A 4D 08 F6 C1 01 74 0A DB 2D B0 D7 41 00 DB 5D 08 9B F6 C1 08 74 10 9B DF E0 DB 2D B0 D7 41 00 DD 5D F8 9B 9B DF E0 F6 C1 10 74 0A DB 2D BC D7 41 00 DD 5D F8 9B F6 C1 04 74 09 }
    condition:
        all of them
}

rule Windows_Generic_Threat_eab96cf2 {
    meta:
        id = "yxSO8nQYtUMgPNNYOyZgF"
        fingerprint = "v1_sha256_cc1dfc2c9c5e1fbc6282342dfbf3a6c834fa56fb6fc46569a24fa78535c5845f"
        version = "1.0"
        date = "2024-01-11"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2be8a2c524f1fb2acb2af92bc56eb9377c4e16923a06f5ac2373811041ea7982"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 20 41 52 FF E0 58 41 59 5A 48 8B 12 E9 4B FF FF FF 5D 48 31 DB 53 49 BE 77 69 6E 68 74 74 70 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 53 53 48 89 E1 53 5A 4D 31 C0 4D 31 C9 53 53 }
    condition:
        all of them
}

rule Windows_Generic_Threat_11a56097 {
    meta:
        id = "7BjpVeWD4k6dBGTcRUVkIf"
        fingerprint = "v1_sha256_42f955c079752c787ac70682bc41fa31f3196d30051d7032276a0d4279d59d58"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6E 6F 69 74 70 65 63 78 45 74 61 6D 72 6F 46 65 67 61 6D 49 64 61 42 }
        $a2 = { 65 74 75 62 69 72 74 74 41 65 74 65 6C 6F 73 62 4F }
    condition:
        all of them
}

rule Windows_Generic_Threat_f3bef434 {
    meta:
        id = "7jXgnk7wIho1LAPtdeaKxj"
        fingerprint = "v1_sha256_efba0e1fbe6562a9aeaac23b851c31350e4ac6551e505be4986bddade92ca303"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6F 70 00 06 EB 72 06 26 0A 00 01 45 6F 04 00 00 8F 7B 02 06 26 0A 00 01 44 6F 70 00 06 D5 72 00 00 00 B8 38 1D 2C EB 2C 1A 00 00 00 B8 38 14 04 00 00 8F 7B 00 00 00 BD 38 32 2C 00 00 00 BE 38 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c6f131c5 {
    meta:
        id = "3HB9gLaZNWZNZ7khuUQIV8"
        fingerprint = "v1_sha256_5702a77fee0cd564916abdbfedf76d069bb7a5b6de0c4623150991d52dc02e42"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "247314baaaa993b8db9de7ef0e2998030f13b99d6fd0e17ffd59e31a8d17747a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 20 48 8B 59 08 8B 13 44 8B 43 04 48 83 C3 08 89 D0 44 09 C0 74 07 E8 B6 FF FF FF EB E8 48 83 C4 20 5B C3 53 45 31 DB BB 0D 00 00 00 48 8B 41 10 45 89 DA 49 C1 E2 04 4A 83 3C 10 00 74 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b2a054f8 {
    meta:
        id = "33upjNXYjpohWov0psYGxA"
        fingerprint = "v1_sha256_f64b1666f78646322a4c37dc887d8fcfdb275b0bca812e360579cefd9e323c02"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "63d2478a5db820731a48a7ad5a20d7a4deca35c6b865a17de86248bef7a64da7"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 7E 38 7E 40 7E 44 48 4C 2A 7E 7E 58 5D 5C }
        $a2 = { 39 7B 34 74 26 39 3A 62 3A 66 25 6A }
        $a3 = { 5B 50 44 7E 66 7E 71 7E 77 7E 7C 7E }
    condition:
        all of them
}

rule Windows_Generic_Threat_fcab7e76 {
    meta:
        id = "229bKIppCiKUD5ZT0n5fcI"
        fingerprint = "v1_sha256_90f50d1227b8e462eaa393690dc2b25601444bf80f2108445a0413bff6bedae8"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "67d7e016e401bd5d435eecaa9e8ead341aed2f373a1179069f53b64bda3f1f56"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 FA 00 2B CD 65 50 7C FF CF 34 00 80 41 BF 1E 12 1A F9 20 0F 56 EE 9F BA C0 22 7E 97 FC CB 03 C7 67 9A AE 8A 60 C0 B3 6C 0D 00 2B 2C 78 83 B5 88 03 17 3A 51 4A 1F 30 D2 C0 53 DC 09 7A BF 2D }
    condition:
        all of them
}

rule Windows_Generic_Threat_90e4f085 {
    meta:
        id = "27h01NwD8BHXzcFbtDgs1w"
        fingerprint = "v1_sha256_2afeae6de965ae155914dcedbfe375327a9fca3b42733c23360dd4fddfcc8a3d"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1a6a290d98f5957d00756fc55187c78030de7031544a981fd2bb4cfeae732168"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 39 39 21 3A 37 3B 45 3C 50 3D 5B 3E 66 3F }
        $a2 = { 66 32 33 39 20 3A 4E 3D 72 68 74 76 48 }
        $a3 = { 32 78 37 7A 42 5A 4C 22 2A 66 49 7A 75 }
    condition:
        all of them
}

rule Windows_Generic_Threat_04a9c177 {
    meta:
        id = "4lKuJoOWw57JPwzdneQnDn"
        fingerprint = "v1_sha256_ca7cf71228b1e13ec05c62cd9924ea5089fdf903d8ea4a5151866996ea81e01e"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0cccdde4dcc8916fb6399c181722eb0da2775d86146ce3cb3fc7f8cf6cd67c29"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6F 81 00 06 FE 3C A3 C3 D6 37 16 00 C2 87 21 EA 80 33 09 E5 00 2C 0F 24 BD 70 BC CB FB 00 94 5E 1B F8 14 F6 E6 95 07 01 CD 02 B0 D7 30 25 65 99 74 01 D6 A4 47 B3 20 AF 27 D8 11 7F 03 57 F6 37 }
    condition:
        all of them
}

rule Windows_Generic_Threat_45d1e986 {
    meta:
        id = "6Gf6yfZugkCIU1zshdU74U"
        fingerprint = "v1_sha256_d53a4d189b9a49f9b6477e12bce0d41e62827306d1df79e6494ab67669d84f35"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 45 00 06 00 00 00 08 28 45 00 09 00 00 00 14 28 45 00 09 00 00 00 20 28 45 00 07 00 00 00 28 28 45 00 0A 00 00 00 34 28 45 00 0B 00 00 00 40 28 45 00 09 00 00 00 5B 81 45 00 00 00 00 00 4C }
    condition:
        all of them
}

rule Windows_Generic_Threat_83c38e63 {
    meta:
        id = "6S4KqzmFUkKlUmZHDOftSL"
        fingerprint = "v1_sha256_89d4036290a29b372918205bba85698d6343109503766cbb13999b5177fc3152"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2121a0e5debcfeedf200d7473030062bc9f5fbd5edfdcd464dfedde272ff1ae7"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 32 65 65 64 36 35 36 64 64 35 38 65 39 35 30 35 62 34 33 39 35 34 32 30 31 39 36 66 62 33 35 36 }
        $a2 = { 34 2A 34 4A 34 52 34 60 34 6F 34 7C 34 }
    condition:
        all of them
}

rule Windows_Generic_Threat_bd24be68 {
    meta:
        id = "K2UzWu7UuwxPOCCpwo4SJ"
        fingerprint = "v1_sha256_8536593696930d03f1e62586886f0df5438d13fb796b4605df7ad67d9633d5f9"
        version = "1.0"
        date = "2024-01-12"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fd159cf2f9bd48b0f6f5958eef8af8feede2bcbbea035a7e56ce1ff72d3f47eb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 4D 0C 56 8B 75 08 89 0E E8 AB 17 00 00 8B 48 24 89 4E 04 E8 A0 17 00 00 89 70 24 8B C6 5E 5D C3 55 8B EC 56 E8 8F 17 00 00 8B 75 08 3B 70 24 75 0E 8B 76 04 E8 7F 17 00 00 89 70 24 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a0c7b402 {
    meta:
        id = "1fLXvixcI7vCyD9EsqbpPO"
        fingerprint = "v1_sha256_d0aa75debbefb301b9fc46ceca4944ae8c4b009118214a9589440b59089b853e"
        version = "1.0"
        date = "2024-01-16"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5814d7712304800d92487b8e1108d20ad7b44f48910b1fb0a99e9b36baa4333a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 57 56 83 E4 F8 83 EC 20 8B 75 10 8B 7D 0C 89 E0 8D 4C 24 18 6A 05 6A 18 50 51 FF 75 08 68 BC 52 4D 90 E8 26 00 00 00 83 C4 18 85 FF 74 06 8B 4C 24 08 89 0F 85 F6 74 08 80 7C 24 15 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_42b3e0d7 {
    meta:
        id = "6ssx6cE2XBI0JujmpxgDoj"
        fingerprint = "v1_sha256_58b4c667b6d796f4525afeb706394f593d03393e3a48e2a0b7664f121e6a78fe"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "99ad416b155970fda383a63fe61de2e4d0254e9c9e09564e17938e8e2b49b5b7"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 F8 53 33 DB 6A 00 8D 45 F8 50 8B 45 0C 50 8B 45 10 50 6A 00 6A 00 33 C9 33 D2 8B 45 08 E8 B1 F7 FF FF 85 C0 75 05 BB 01 00 00 00 8B C3 5B 59 59 5D C2 0C 00 8D 40 00 53 BB E0 E1 }
    condition:
        all of them
}

rule Windows_Generic_Threat_66142106 {
    meta:
        id = "7NHogvgcdX4b7cMuMuyt9u"
        fingerprint = "v1_sha256_bf5d8db3ed6d2abc3158b04e904351250bf17a6d766e31769b3c5a6e534165b0"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "cd164a65fb2a496ad7b54c782f25fbfca0540d46d2c0d6b098d7be516c4ce021"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 10 6A 00 8D 4D F0 E8 6B FF FF FF 8B 45 F4 BA E9 FD 00 00 39 50 08 74 0C E8 29 48 00 00 33 D2 85 C0 75 01 42 80 7D FC 00 74 0A 8B 4D F0 83 A1 50 03 00 00 FD 8B C2 C9 C3 8B FF 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_51a1d82b {
    meta:
        id = "2yyYfzaBNMHtWvaqZ8ZyY1"
        fingerprint = "v1_sha256_2d6b0560e1980deb6aad8e0902d065eeda406506b70bb8bb27c7fa58be9842f8"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1a7adde856991fa25fac79048461102fba58cda9492d4f5203b817d767a81018"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 04 53 56 57 89 4D FC 8B 45 FC 50 FF 15 D0 63 41 00 5F 5E 5B C9 C3 CC CC CC CC CC 66 8B 01 56 66 8B 32 57 66 3B F0 72 44 75 0A 66 8B 79 02 66 39 7A 02 72 38 66 3B F0 75 14 66 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_dee3b4bf {
    meta:
        id = "1qMRujUbpP7oywuDcLN8iv"
        fingerprint = "v1_sha256_cfd7f9250ab44ffe12b62f84ae753032642d9aa2524d88a6d4d989a2afa043a3"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c7f4b63fa5c7386d6444c0d0428a8fe328446efcef5fda93821f05e86efd2fba"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 4A 75 73 74 20 63 6F 70 79 20 74 68 65 20 70 61 74 63 68 20 74 6F 20 74 68 65 20 70 72 6F 67 72 61 6D 20 64 69 72 65 63 74 6F 72 79 20 61 6E 64 20 61 70 70 6C 79 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_fdbcd3f2 {
    meta:
        id = "2XUM0A21GtwEJvf78RHcjV"
        fingerprint = "v1_sha256_ca9136ca44a61795cca44ac9bb0494fdc34c08d6578603ba3be3582956f4a98f"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9258e4fe077be21ad7ae348868f1ac6226f6e9d404c664025006ab4b64222369"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 FC 60 8B 75 0C 8D A4 24 00 00 00 00 8D A4 24 00 00 00 00 90 56 E8 22 00 00 00 0B C0 75 05 89 45 FC EB 11 89 35 84 42 40 00 46 8B 5D 08 38 18 75 E3 89 45 FC 61 8B 45 FC C9 C2 08 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b7852ccf {
    meta:
        id = "iOVisQoqfOblXhFAxRgC"
        fingerprint = "v1_sha256_4d5c29cceaacfda0c41bcd13cf95e90397b1b6c0c6beeb19b9184f435c8669b9"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5ac70fa959be4ee37c0c56f0dd04061a5fed78fcbde21b8449fc93e44a8c133a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 45 2B 34 2C 3D 43 4A 32 3A 24 40 2F 22 3E 3F 3C 24 44 }
        $a2 = { 67 6F 72 67 65 6F 75 73 68 6F 72 6E 79 }
        $a3 = { 62 6C 61 63 6B 20 68 61 69 72 75 6E 73 68 61 76 65 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c3c8f21a {
    meta:
        id = "6oTeSE44bsxnOzqHQbVHnc"
        fingerprint = "v1_sha256_b4d2b28fb2c9d46884b0b34f7821151b88891a8d881885c704e0e192cf7fca70"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9a102873dd37d08f53dcf6b5dad2555598a954d18fb3090bbf842655c5fded35"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 83 EC 14 53 56 57 8D 7D F7 BE 1E CA 40 00 B9 02 00 00 00 F3 A5 A4 68 62 CA 40 00 68 64 CA 40 00 E8 A8 25 00 00 83 C4 08 89 C3 8D 45 EC 50 E8 CA 24 00 00 59 8D 45 EC 50 E8 80 26 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a3d51e0c {
    meta:
        id = "R9MB9HTR9cOOUYImbGjZ4"
        fingerprint = "v1_sha256_f128f6a037abb4af2c11605b182852146780be6451b3062a2914bedb5c286843"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "18bd25df1025cd04b0642e507b0170bc1a2afba71b2dc4bd5e83cc487860db0d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 53 56 8B 75 08 33 DB 39 5D 14 57 75 10 3B F3 75 10 39 5D 0C 75 12 33 C0 5F 5E 5B 5D C3 3B F3 74 07 8B 7D 0C 3B FB 77 1B E8 05 F8 FF FF 6A 16 5E 89 30 53 53 53 53 53 E8 97 F7 FF FF 83 }
    condition:
        all of them
}

rule Windows_Generic_Threat_54ccad4d {
    meta:
        id = "50x91chJzt5bxRq2jhxSZB"
        fingerprint = "v1_sha256_b9fb525be22dd2f235c3ac68688ced5298da45194ad032423689f5a085df6e31"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fe4aad002722d2173dd661b7b34cdb0e3d4d8cd600e4165975c48bf1b135763f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 4D 55 73 65 72 4E 61 74 69 66 65 72 63 }
        $a2 = { 4D 79 52 65 67 53 61 76 65 52 65 63 6F 72 64 }
        $a3 = { 53 74 65 61 6C 65 72 54 69 6D 65 4F 75 74 }
    condition:
        all of them
}

rule Windows_Generic_Threat_6ee18020 {
    meta:
        id = "6eAT8EtfEAS1qIoklQm2j0"
        fingerprint = "v1_sha256_8a08973ae2ddde275e007686fc6eca831c1fb398b7221d5022da10f90da0e44d"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d58d8f5a7efcb02adac92362d8c608e6d056824641283497b2e1c1f0e2d19b0a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 53 8B 5D 0C 8B 45 08 50 E8 9C 19 02 00 59 89 03 89 53 04 83 7B 04 00 75 07 83 3B 00 76 10 EB 02 7E 0C C6 43 28 01 33 C0 5B 5D C3 5B 5D C3 B8 01 00 00 00 5B 5D C3 90 90 90 55 8B EC 53 }
    condition:
        all of them
}

rule Windows_Generic_Threat_8eb547db {
    meta:
        id = "3VS2WV7znOymFNZRHJxbDu"
        fingerprint = "v1_sha256_73cabad0656c6b347def017b07138fdbdd5b41da5ccf7d701fea764669058f39"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3fc821b63dfa653b86b11201073997fa4dc273124d050c2a7c267ac789d8a447"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0D 00 00 04 2D 0A 28 23 00 00 06 28 19 00 00 06 7E 14 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A 13 30 01 00 41 00 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_803feff4 {
    meta:
        id = "17WZeiifBFCe8ajKXiqPcB"
        fingerprint = "v1_sha256_e22b8b208ff104e2843d897c425467f2f0ec0c586c4db578da90aeaef0209e1d"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "8f150dfb13e4a2ff36231f873e4c0677b5db4aa235d8f0aeb41e02f7e31c1e05"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6F 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 8D 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 92 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 9A 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 }
    condition:
        all of them
}

rule Windows_Generic_Threat_9c7d2333 {
    meta:
        id = "4gQzaUMiVUaFMBgnVRTEax"
        fingerprint = "v1_sha256_561290ebf3ca2a01914f514d63121be930e7a8c06cfc90ff4b8f0c7cef3408fe"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "85219f1402c88ab1e69aa99fe4bed75b2ad1918f4e95c448cdc6a4b9d2f9a5d4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 81 EC 64 09 00 00 57 C6 85 00 F8 FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 F8 FF FF F3 AB 66 AB AA C6 85 00 FC FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 FC FF FF F3 AB 66 AB AA C7 85 AC F6 }
    condition:
        all of them
}

rule Windows_Generic_Threat_747b58af {
    meta:
        id = "1Pc6x3mEyKL4RMlONloc7r"
        fingerprint = "v1_sha256_fd6b36ca50c1017035474b491f716bfb0d53b181fce4b5478a57a1d1a6ddc3e7"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ee28e93412c59d63155fd79bc99979a5664c48dcb3c77e121d17fa985fcb0ebe"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5C 43 3D 5D 78 48 73 66 40 22 33 2D 34 }
        $a2 = { 79 5A 4E 51 61 4A 21 43 43 56 31 37 74 6B }
        $a3 = { 66 72 7A 64 48 49 2D 4E 3A 4D 23 43 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c3c4e847 {
    meta:
        id = "4CxftzmDAeWNjWkNvYMEIg"
        fingerprint = "v1_sha256_fa147abf7aa872f409e7684c4c60485fc58f57543062573526e56ff9866f8dfe"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "86b37f0b2d9d7a810b5739776b4104f1ded3a1228c4ec2d104d26d8eb26aa7ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 2E 3F 41 56 3F 24 5F 52 65 66 5F 63 6F 75 6E 74 40 55 41 70 69 44 61 74 61 40 40 40 73 74 64 40 40 }
    condition:
        all of them
}

rule Windows_Generic_Threat_6542ebda {
    meta:
        id = "6U07i7el1EjHZMfxdIaeXt"
        fingerprint = "v1_sha256_30263341bf51a001503dfda9be5771d401bc5b5423682c29a6d4ebc457415d3e"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2073e51c7db7040c6046e36585873a0addc2bcddeb6e944b46f96c607dd83595"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 53 56 57 8B F9 85 D2 74 18 0F B7 02 8D 5A 02 0F B7 72 02 8B 4A 04 3B C7 74 0E 83 C2 08 03 D1 75 E8 33 C0 5F 5E 5B 5D C3 B8 78 03 00 00 66 3B F0 74 EF 8B 45 08 89 18 8D 41 06 EB E7 8D }
    condition:
        all of them
}

rule Windows_Generic_Threat_1417511b {
    meta:
        id = "3gZRV625IdrypLaKYwIQqL"
        fingerprint = "v1_sha256_e6b53082fa447ac3cf56784771aca742696922e6f740a24d014e04250dc5020c"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2fc9bd91753ff3334ef7f9861dc1ae79cf5915d79fa50f7104cbb3262b7037da"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 20 8B 45 08 89 45 F4 8B 4D F4 8B 55 08 03 51 3C 89 55 F0 B8 08 00 00 00 6B C8 00 8B 55 F0 8B 45 08 03 44 0A 78 89 45 F8 8B 4D F8 8B 55 08 03 51 20 89 55 EC 8B 45 F8 8B 4D 08 03 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7526f106 {
    meta:
        id = "6HoDKU5QHdNkPOZvrbaOYX"
        fingerprint = "v1_sha256_a0f9eb760be05196f0c5c3e3bf250929b48341a58a11c24722978fa19c4a9f57"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5a297c446c27a8d851c444b6b32a346a7f9f5b5e783564742d39e90cd583e0f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 50 72 6F 6A 65 63 74 31 2E 75 45 78 57 61 74 63 68 }
        $a2 = { 6C 49 45 4F 62 6A 65 63 74 5F 44 6F 63 75 6D 65 6E 74 43 6F 6D 70 6C 65 74 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_cbe3313a {
    meta:
        id = "1iW3xWISh7cV9oQIjaCgsq"
        fingerprint = "v1_sha256_41a731cefe0c8ee95f1db598b68a8860ef7ff06137ce94d0dd0b5c60c4240e85"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1ca2a28c851070b9bfe1f7dd655f2ea10ececef49276c998a1d2a1b48f84cef3"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 08 68 E6 25 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 53 56 57 89 65 F8 C7 45 FC D0 25 40 00 A1 94 B1 41 00 33 F6 3B C6 89 75 EC 89 75 E8 89 75 E4 0F 8E E7 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_779cf969 {
    meta:
        id = "3DM9fPDxDFQmZGvZnzWlVP"
        fingerprint = "v1_sha256_ad0f2d78386abf4c6dc6b5a4a88b4dcf8e5bf8086b08bac91e5e00be9936e908"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ef281230c248442c804f1930caba48f0ae6cef110665020139f826ab99bbf274"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 3E 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 50 79 74 68 6F 6E 20 53 6F 66 74 77 61 72 65 20 46 6F 75 6E 64 61 74 69 6F 6E 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_d568682a {
    meta:
        id = "3LfI5jnSvQGp6296wKqQPS"
        fingerprint = "v1_sha256_97e172502037c7a5d66327fcc4a237e5548694fc7d73a535838ad56367f15d76"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0d98bc52259e0625ec2f24078cf4ae3233e5be0ade8f97a80ca590a0f1418582"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 28 22 00 00 0A 80 19 00 00 04 28 53 00 00 06 28 2D 00 00 0A 28 5D 00 00 06 16 80 1D 00 00 04 7E 13 00 00 04 7E 15 00 00 04 16 7E 15 00 00 04 8E B7 16 14 FE 06 5B 00 00 06 73 79 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ccb6a7a2 {
    meta:
        id = "42mc03beORExIFAasqteqC"
        fingerprint = "v1_sha256_312265bbc4330a463bbe7478c70233f5df3353bda3c450562f2414f3675ba91e"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "60503212db3f27a4d68bbfc94048ffede04ad37c78a19c4fe428b50f27af7a0d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 40 52 61 6E 67 65 3A 62 79 74 65 73 3D 30 2D }
        $a2 = { 46 49 77 41 36 4B 58 49 75 4E 66 4B 71 49 70 4B 30 4D 57 4D 74 49 38 4B 67 4D 68 49 39 4B 30 4D 53 49 6A 4B 66 4D 73 49 76 4B 75 4D 64 49 70 4B 30 4D 73 49 66 4B 68 4D 6F 49 69 43 6F 4D 6C 49 71 4B }
    condition:
        all of them
}

rule Windows_Generic_Threat_d62f1d01 {
    meta:
        id = "1hDzzmhiZmJeDZfI0JPWlk"
        fingerprint = "v1_sha256_fd65eb56f3a48c37f83d3544c039d29c231cac1e2f8f07d176d709432a75a4c3"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "380892397b86f47ec5e6ed1845317bf3fd9c00d01f516cedfe032c0549eef239"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 56 8B 75 08 33 C0 57 8B FE AB AB AB 8B 7D 0C 8B 45 10 03 C7 89 45 FC 3B F8 73 3F 0F B7 1F 53 E8 01 46 00 00 59 66 3B C3 75 28 83 46 04 02 83 FB 0A 75 15 6A 0D 5B 53 E8 E9 45 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2bb6f41d {
    meta:
        id = "vRwcpEHWLM0N9IFLxmyR7"
        fingerprint = "v1_sha256_7c4e62b69880eb8a901d7e94b7539786e8ac58808df07cb1cbe9ff45efce518e"
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "afa060352346dda4807dffbcac75bf07e8800d87ff72971b65e9805fabef39c0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
        $a2 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }
        $a3 = { 42 72 6F 77 73 65 72 50 61 74 68 54 6F 41 70 70 4E 61 6D 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c54ed0ed {
    meta:
        id = "1ihbv7cEtLYlOPC3TsvUqw"
        fingerprint = "v1_sha256_f0f4878cb003371522ed1419984f15fd5049f1adeb8e051b8b51b31b0d620e96"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 81 FA 00 10 00 00 72 1C 48 83 C2 27 4C 8B 41 F8 49 2B C8 48 8D 41 F8 48 83 F8 1F 0F 87 92 00 00 00 49 8B C8 ?? ?? ?? ?? ?? 48 83 63 10 00 33 C0 EB 58 4D 8B CC 4D 8B C7 49 8B D6 48 8B CE FF D0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dbe41439 {
    meta:
        id = "6EZ4QtS2r8WgwIAHfx3uzi"
        fingerprint = "v1_sha256_288cdc285d024f2b69847e0d49bd4dc1c86a2a6a24a7b4fb248071855ba39a38"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "64afd2bc6cec17402473a29b94325ae2e26989caf5a8b916dc21952149d71b00"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 E4 F8 83 EC 2C 53 56 8B F1 57 89 74 24 10 8B 46 1C 8B 08 85 C9 74 23 8B 56 2C 8B 3A 8D 04 0F 3B C8 73 17 8D 47 FF 89 02 8B 4E 1C 8B 11 8D 42 01 89 01 0F B6 02 E9 F1 00 00 00 33 DB }
    condition:
        all of them
}

rule Windows_Generic_Threat_51a52b44 {
    meta:
        id = "4x8amQ7TxZHyz4EUDvZ9Ef"
        fingerprint = "v1_sha256_aad1c350f43cf2e0512e085e1a04db6099c568e375423afb9518b1fb89801c21"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "303aafcc660baa803344bed6a3a7a5b150668f88a222c28182db588fc1e744e0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 40 6A 67 72 72 6C 6E 68 6D 67 65 77 77 68 74 69 63 6F 74 6D 6C 77 6E 74 6A 6A 71 68 72 68 62 74 75 64 72 78 7A 63 72 67 65 78 65 70 71 73 7A 73 75 78 6B 68 6E 79 63 74 72 63 63 7A 6D 63 63 69 63 61 61 68 70 66 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5c18a7f9 {
    meta:
        id = "1evr1Drv6Mqt86GvGaoIVB"
        fingerprint = "v1_sha256_05cea396567ed3e23907dec4e6e3a6629cd1044d9123cde0575a04b73bae6c20"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fd272678098eae8f5ec8428cf25d2f1d8b65566c59e363d42c7ce9ffab90faaa"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 5D E9 CD 1A 00 00 8B FF 55 8B EC 51 FF 75 08 C7 45 FC 00 00 00 00 8B 45 FC E8 03 1B 00 00 59 C9 C3 8B FF 55 8B EC 51 56 57 E8 6B 18 00 00 8B F0 85 F6 74 1C 8B 16 8B CA 8D 82 90 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ab01ba9e {
    meta:
        id = "3NHZ2MOK1A4DAl2HloOJWD"
        fingerprint = "v1_sha256_cc8d79950e21270938d2ea7e501c7c8fdbebe92767b48b46bb03c08c377e095b"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2b237716d0c0c9877f54b3fa03823068728dfe0710c5b05e9808eab365a1408e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 53 3C 3B 54 24 38 74 23 45 3B 6C 24 2C }
        $a2 = { 3A 3D 3B 47 3B 55 3B 63 3B 6A 3B 7A 3B }
        $a3 = { 56 30 61 30 6B 30 77 30 7C 30 24 39 32 39 37 39 41 39 4F 39 5D 39 64 39 75 39 }
    condition:
        all of them
}

rule Windows_Generic_Threat_917d7645 {
    meta:
        id = "4EnF5o0j35ilC9xymYoHSW"
        fingerprint = "v1_sha256_65748ff2e4448f305b9541ea9864cc6bda054d37be5ed34110a2f64c8fef30c7"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "19b54a20cfa74cbb0f4724155244b52ca854054a205be6d148f826fa008d6c55"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 E4 E0 56 57 53 81 EC D4 0A 00 00 8B D9 8B F2 BA 1D 00 00 00 FF 73 1C 8D 8C 24 BC 0A 00 00 E8 19 A1 02 00 6A 00 FF B4 24 BC 0A 00 00 8D 8C 24 A8 0A 00 00 E8 D4 06 03 00 8D 8C 24 B8 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7a09e97d {
    meta:
        id = "12xab9BPAu6bkO9EQaQZsV"
        fingerprint = "v1_sha256_b65b2d12901953c137687a7b466c78e0537a2830c37a4cb13dd0eda457bba937"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c0c1e333e60547a90ec9d9dac3fc6698b088769bc0f5ec25883b2c4d1fd680a9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 06 2A 3A FE 09 00 00 FE 09 01 00 6F 8D 00 00 0A 2A 00 4A FE 09 00 00 FE 09 01 00 FE 09 02 00 6F 8E 00 00 0A 2A 00 1E 00 28 43 00 00 06 2A 5A FE 09 00 00 FE 09 01 00 FE 09 02 00 FE 09 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dc4ede3b {
    meta:
        id = "1VJguEe2HETSGXrTxLjDLw"
        fingerprint = "v1_sha256_c402d5f16f2be32912d7a054b51ab6dafc6173bb5a267a7846b3ac9df1c4c19f"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c49f20c5b42c6d813e6364b1fcb68c1b63a2f7def85a3ddfc4e664c4e90f8798"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 83 EC 28 C7 45 FC 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 10 03 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 04 00 00 00 80 8B 45 08 }
    condition:
        all of them
}

rule Windows_Generic_Threat_bb480769 {
    meta:
        id = "6GHzUSEty8xKWPT09fxT9A"
        fingerprint = "v1_sha256_1087e0befceac2606ce5dc5f2b42b45ebad888e7d3e451c3fb89de7e932a31f5"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "010e3aeb26533d418bb7d2fdcfb5ec21b36603b6abb63511be25a37f99635bce"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 C6 45 03 B8 C7 45 08 BA EF BE AD C7 45 0C DE 89 10 BA C7 45 10 EF BE AD DE C7 45 14 89 50 04 B8 C7 45 18 EF BE AD DE C7 45 1C 6A 00 6A 01 C7 45 20 6A 00 FF D0 C7 45 24 B8 EF BE AD C7 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5fbf5680 {
    meta:
        id = "5NFVlc2F2NvgXpof6qPEBY"
        fingerprint = "v1_sha256_ec5399f6fb29125cb4c096851b9194fa35fb1e5ddd1f4d4f07b155471ae5c619"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1b0553a9873d4cda213f5464b5e98904163e347a49282db679394f70d4571e77"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 3C 56 57 8B 45 08 50 E8 51 AF 00 00 83 C4 04 89 45 FC 8B 45 FC 83 C0 58 99 8B C8 8B F2 8B 45 08 99 2B C8 1B F2 89 4D F8 66 0F 57 C0 66 0F 13 45 EC C7 45 DC FF FF FF FF C7 45 E0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_aa30a738 {
    meta:
        id = "2weaRYwtrwc5yVsBHqHHzg"
        fingerprint = "v1_sha256_64967fbc0e74435452752731a8b9385345cc771d27ee33cd018cccdeb26bb75e"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7726a691bd6c1ee51a9682e0087403a2c5a798ad172c1402acf2209c34092d18"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 55 0C 85 D2 75 04 33 C0 5D C3 8B 45 08 53 56 8B 75 10 83 FE 08 57 F7 D0 B9 FF 00 00 00 0F 8C D1 00 00 00 8B FE C1 EF 03 8B DF F7 DB 8D 34 DE 89 75 10 0F B6 1A 8B F0 23 F1 33 F3 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_9a8dc290 {
    meta:
        id = "1mCgcaJMjNUYO6rAHmMl9e"
        fingerprint = "v1_sha256_0097a13187b953ebe97809dda2be818cfcd94991c03e75f344e34a3d2c4fe902"
        version = "1.0"
        date = "2024-01-21"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d951562a841f3706005d7696052d45397e3b4296d4cd96bf187920175fbb1676"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6F 01 00 06 FE 0E 0B 00 FE 0C 0B 00 FE 0C 09 00 6F 78 01 00 06 FE 0C 0B 00 FE 0C 08 00 28 F2 00 00 06 6F 74 01 00 06 FE 0C 0B 00 FE 0C 07 00 28 F2 00 00 06 6F 76 01 00 06 FE 0C 0B 00 FE 09 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_bbf2a354 {
    meta:
        id = "7mQOocTHtZg2SngIedmh7H"
        fingerprint = "v1_sha256_6be2fae41199daea6b9d0394c9af7713543333a50620ef417bb8439d5a07f336"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b4e6c748ad88070e39b53a9373946e9e404623326f710814bed439e5ea61fc3e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 54 68 61 74 20 70 72 6F 67 72 61 6D 20 6D 75 73 74 20 62 65 20 72 75 6E 20 75 6E 64 65 72 20 57 69 6E 33 32 }
    condition:
        all of them
}

rule Windows_Generic_Threat_da0f3cbb {
    meta:
        id = "5zVljjgpteQdS7VsM3Sbm"
        fingerprint = "v1_sha256_262d0bbb69adde8c4c8645813b048f3aaa2dbcc83996606e7ca21c3edea2b5d8"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b2c456d0051ffe1ca7e9de1e944692b10ed466eabb38242ea88e663a23157c58"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 45 0C 53 56 83 F8 FF 57 8B F1 74 03 89 46 10 8B 7D 08 33 DB 3B FB 75 17 FF 76 04 E8 C6 09 00 00 59 89 5E 04 89 5E 0C 89 5E 08 E9 D9 00 00 00 8B 4E 04 3B CB 75 23 8D 1C 3F 53 E8 7E }
    condition:
        all of them
}

rule Windows_Generic_Threat_7d555b55 {
    meta:
        id = "1OF4ujVOPaAczqZ7gSORX4"
        fingerprint = "v1_sha256_dc3a3622abbc7d0a02d8d9ed4446d0a72a603ecfd6594ecfa615e5418a9c9970"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7efa5c8fd55a20fbc3a270cf2329d4a38f10ca372f3428bee4c42279fbe6f9c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 40 53 56 57 6A 0F 59 BE 84 77 40 00 8D 7D C0 8B 5D 0C F3 A5 66 A5 8B CB 33 C0 A4 8B 7D 08 8B D1 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA 33 C0 8D 7D 0E 50 66 AB FF 15 BC 60 40 00 50 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0a38c7d0 {
    meta:
        id = "5Gnj1QKgeuNsRKzzQNzyZ1"
        fingerprint = "v1_sha256_e3fde76825772683c57f830759168fc9a3b3f3387f091828fd971e9ebba06d8a"
        version = "1.0"
        date = "2024-01-22"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "69ea7d2ea3ed6826ddcefb3c1daa63d8ab53dc6e66c59cf5c2506a8af1c62ef4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 4D 08 85 C9 74 37 8B 45 0C 3D E0 10 00 00 7C 05 B8 E0 10 00 00 85 C0 7E 24 8D 50 FF B8 AB AA AA AA F7 E2 D1 EA 83 C1 02 42 53 8B FF 8A 41 FE 8A 19 88 59 FE 88 01 83 C1 03 4A 75 F0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_98527d90 {
    meta:
        id = "2F0OLsxN8D0y2tq5H59J3A"
        fingerprint = "v1_sha256_5a93f0a372f3a51233c6b2334539017df922f35a0d5f7d1749e0dd79268cb836"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fa24e7c6777e89928afa2a0afb2fab4db854ed3887056b5a76aef42ae38c3c82"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 20 FF D5 48 8D 87 0F 02 00 00 80 20 7F 80 60 28 7F 4C 8D 4C 24 20 4D 8B 01 48 89 DA 48 89 F9 FF D5 48 83 C4 28 5D 5F 5E 5B 48 8D 44 24 80 6A 00 48 39 C4 75 F9 48 83 EC 80 E9 8D 70 FC }
    condition:
        all of them
}

rule Windows_Generic_Threat_baba80fb {
    meta:
        id = "BIl6sfw8MOvNSmm6g8tTf"
        fingerprint = "v1_sha256_ba0da35bc00b776ae9b427e3a4b312b1b75bdc9b972fb52f26a5df6737f1ddc9"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "dd22cb2318d66fa30702368a7f06e445fba4b69daf9c45f8e83562d2c170a073"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 0C 8B 4D 0C 53 56 57 8B 59 20 8D 71 20 8B F9 89 75 FC 85 DB 89 7D 0C 75 05 8B 59 24 EB 0C 8D 41 24 89 45 F8 8B 00 85 C0 75 30 8B 51 28 8B 41 2C 85 DB 74 03 89 53 28 85 D2 74 15 }
    condition:
        all of them
}

rule Windows_Generic_Threat_9f4a80b2 {
    meta:
        id = "5Ir9Jq3kytmb3p09ofqPtc"
        fingerprint = "v1_sha256_1df3b8245bc0e995443d598feb5fe2605e05df64b863d4f47c17ecbe8d28c3ea"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "47d57d00e2de43f33cd56ff653adb59b804e4dbe37304a5fa6a202ee20b50c24"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 2A 20 02 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 00 00 00 00 FE 01 39 0A 00 00 00 00 20 01 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 02 00 00 00 FE 01 39 05 00 00 00 38 05 00 00 00 38 }
    condition:
        all of them
}

rule Windows_Generic_Threat_39e1eb4c {
    meta:
        id = "2c2rfol4mfDonop0D200zX"
        fingerprint = "v1_sha256_d7791ae7513bc5645bcfa93a2d7bf9f7ef47a6727ea2ba5eb85f3c8528761429"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "a733258bf04ffa058db95c8c908a79650400ebd92600b96dd28ceecac311f94a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 E4 F8 83 EC 6C 53 56 8B 75 08 57 8B C6 8D 4C 24 58 E8 26 80 00 00 8B C6 8D 4C 24 38 E8 1B 80 00 00 80 7C 24 54 00 8B 7E 0C 8B 5E 08 89 7C 24 1C 74 09 8B 74 24 50 E8 61 80 00 00 83 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d51dd31b {
    meta:
        id = "2l9YaIuWBhwyAsIodyfbMQ"
        fingerprint = "v1_sha256_85fc7aa81489b304c348ead2d7042bb5518ff4579b1d3e837290032c4b144e47"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2a61c0305d82b6b4180c3d817c28286ab8ee56de44e171522bd07a60a1d8492d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 7E 7D 7C 7B 7A 79 78 78 76 77 74 73 72 }
        $a2 = { 6D 6C 6B 6A 69 68 67 66 65 64 63 62 61 60 60 5E 66 60 5B 5A }
    condition:
        all of them
}

rule Windows_Generic_Threat_3a321f0a {
    meta:
        id = "7fElkUox5rzJlZpOCYobKN"
        fingerprint = "v1_sha256_83834dd7d4df5de4b6a032f1896f52c1ebdf16ca8ad9766e8872243f1a6da67e"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "91056e8c53dc1e97c7feafab31f0943f150d89a0b0026bcfb3664d2e93ccfe2b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 44 8D 45 14 8B 4D 10 85 C9 89 5D F8 89 7D FC 0F 8E 3D 01 00 00 49 8D 55 17 83 E2 FC 89 4D 10 85 C9 8D 42 08 8B 58 F8 8B 78 FC 89 5D D4 89 7D D8 0F 8E 31 01 00 00 83 C2 0B 49 83 }
    condition:
        all of them
}

rule Windows_Generic_Threat_a82f45a8 {
    meta:
        id = "7amBD1toTt1Wn7Ce5afIs6"
        fingerprint = "v1_sha256_70ebab6b03af38ef8c81664cf49ab07066a9672666599d99c91291a9d2e3af0b"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ad07428104d3aa7abec2fd86562eaa8600d3e4b0f8d78ba1446f340d10008b53"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 89 4D FC 8B 4D 08 51 8B 4D FC 83 C0 04 E8 66 7D F6 FF 59 5D C2 08 00 90 55 8B EC 51 89 4D FC 8B 4D 08 51 41 51 8B 4D FC E8 CF FF FF FF 59 5D C2 04 00 8B C0 55 8B EC 83 C4 F8 53 56 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d6625ad7 {
    meta:
        id = "33lK7YXCqbKSfL1AePyAL9"
        fingerprint = "v1_sha256_e90aff7c35f60cc3446f9eeb2131edb7125bfa04eb8f90c5671d06e9ff269755"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "878c9745320593573597d62c8f3adb3bef0b554cd51b18216f6d9f5d1a32a931"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 2E 3F 41 56 3C 6C 61 6D 62 64 61 5F 31 3E 40 3F 4C 40 3F 3F 6F 6E 5F 65 76 65 6E 74 5F 61 64 64 40 43 6F 6D 70 6F 6E 65 6E 74 5F 4B 65 79 6C 6F 67 65 72 40 40 45 41 45 58 49 40 5A 40 }
    condition:
        all of them
}

rule Windows_Generic_Threat_61bbb571 {
    meta:
        id = "4CcwXTka7PWmf9dPYQGdOj"
        fingerprint = "v1_sha256_6b1ec666f3689638b9db9f041b0a89660b27c32590b747c5da3f4a02f01c7112"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "41e2a6cecb1735e8f09b1ba5dccff3c08afe395b6214396e545347927d1815a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 14 8B 45 08 53 56 57 8B F9 BE 49 92 24 09 6A 1C 59 89 7D F8 2B 07 99 F7 F9 89 45 FC 8B 47 04 2B 07 99 F7 F9 89 45 F0 3B C6 0F 84 E5 00 00 00 8D 58 01 8B 47 08 2B 07 99 F7 F9 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_4a605e93 {
    meta:
        id = "7AhUpbO5Ai75yFzh5nbdJZ"
        fingerprint = "v1_sha256_6ad7afa5bd03916917e2bbf4d736331f4319b20bfde296d7e62315584813699f"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1a84e25505a54e8e308714b53123396df74df1bde223bb306c0dc6220c1f0bbb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 20 48 8B 19 45 33 C0 48 85 DB 74 65 4C 89 01 48 83 FA FF 75 17 41 8B C0 44 38 03 74 2D 48 8B CB 48 FF C1 FF C0 44 38 01 75 F6 EB 1E 48 83 FA FE 75 1B 41 8B C0 66 44 39 03 74 0F 48 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_b509dfc8 {
    meta:
        id = "6JI7VcYJqaLWngrQdsBzOA"
        fingerprint = "v1_sha256_90b00caf612f56a898b24c28ae6febda3fd11f382ab1deba522bdd2e2ba254b4"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9b5124e5e1be30d3f2ad1020bbdb93e2ceeada4c4d36f71b2abbd728bd5292b8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 6F 29 00 00 0A 6F 2A 00 00 0A 13 04 11 04 28 22 00 00 0A 28 2B 00 00 0A 2D 0D 11 04 28 22 00 00 0A 28 2C 00 00 0A 26 06 28 2D 00 00 0A 2C 0F 06 73 28 00 00 0A 13 05 11 05 6F 2E 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7a49053e {
    meta:
        id = "6jw6xNudcrawlFH0BTxczq"
        fingerprint = "v1_sha256_6db95f20a2bcdfd7cb37cb33dae6351dd19f51a8c3cae54b1bb034af17378094"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "29fb2b18cfd72a2966640ff59e67c89f93f83fc17afad2dfcacf9f53e9ea3446"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5D 76 3F 3F 32 40 59 41 50 41 58 49 40 5A 66 }
        $a2 = { 41 75 74 68 6F 72 69 7A 61 26 42 61 73 69 63 48 24 }
        $a3 = { 4A 7E 4C 65 61 76 65 47 65 74 51 75 65 }
    condition:
        all of them
}

rule Windows_Generic_Threat_fca7f863 {
    meta:
        id = "63WcHmXTBHrhuvHAOGLs2i"
        fingerprint = "v1_sha256_ad45fe6e8257d012824b36aaee1beccb82c1b78031de86c1f1dd26d5be88aa6f"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9d0e786dd8f1dc05eae910c6bcf15b5d05b4b6b0543618ca0c2ff3c4bb657af3"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 8D 64 24 F4 53 89 C3 6A 0C 8D 45 F4 50 6A 00 FF 53 10 50 FF 53 0C 50 FF 53 24 8B 45 F4 89 43 2C 03 40 3C 8B 40 50 89 43 34 6A 40 68 00 30 00 00 FF 73 34 6A 00 FF 13 89 43 30 8B 4B 34 }
    condition:
        all of them
}

rule Windows_Generic_Threat_cafbd6a3 {
    meta:
        id = "1HoVZYAhMW9MbRnfrPMIhR"
        fingerprint = "v1_sha256_28813fc8a49b6ec3fe7675409fde923f0f30851429a526c142e0a228b4e0efa6"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "97081a51aa016d0e6c9ecadc09ff858bf43364265a006db9d7cc133f8429bc46"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6C 6B 73 6A 66 68 67 6C 6B 6A 66 73 64 67 31 33 31 }
        $a2 = { 72 65 67 20 44 65 6C 65 74 65 20 22 48 4B 4C 4D 5C 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 20 4E 54 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 52 75 6E 4F 6E 63 65 22 20 2F 66 20 3E 20 6E 75 6C }
    condition:
        all of them
}

rule Windows_Generic_Threat_d8f834a9 {
    meta:
        id = "2mMB36wBi0vIAqVW1VIweh"
        fingerprint = "v1_sha256_9fa1a65f3290867e4c59f14242f7261741e792b8be48c053ac320a315f2c1beb"
        version = "1.0"
        date = "2024-01-29"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c118c2064a5839ebd57a67a7be731fffe89669a8f17c1fe678432d4ff85e7929"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 F4 53 56 57 8B F9 8B F2 8B D8 33 D2 8A 55 08 0F AF 53 30 D1 FA 79 03 83 D2 00 03 53 30 8B 43 34 E8 62 48 04 00 89 45 FC 68 20 00 CC 00 8B 45 20 50 57 56 8B 45 FC 8B 10 FF 52 20 }
    condition:
        all of them
}

rule Windows_Generic_Threat_de3f91c6 {
    meta:
        id = "3ghslwd1kfElXwnKaDceBW"
        fingerprint = "v1_sha256_032ac2adb11782d823f50bfedf4e4decb731dbe7d3abbb3b05ccff598ba7edb8"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e2cd4a8ccbf4a3a93c1387c66d94e9506b5981357004929ce5a41fcedfffb20f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 56 8B 75 08 80 7E 04 00 74 08 FF 36 E8 0B 41 00 00 59 83 26 00 C6 46 04 00 5E 5D C3 55 8B EC 8B 45 08 8B 4D 0C 3B C1 75 04 33 C0 5D C3 83 C1 05 83 C0 05 8A 10 3A 11 75 18 84 D2 74 EC }
    condition:
        all of them
}

rule Windows_Generic_Threat_f0516e98 {
    meta:
        id = "44MPwIifYVtvDZuau35Z3B"
        fingerprint = "v1_sha256_28f5b1a05d90745f432aee6bb9da3855d70b18d556153059794c5e53bbd5117c"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "21d01bd53f43aa54f22786d7776c7bc90320ec6f7a6501b168790be46ff69632"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 69 66 20 65 78 69 73 74 20 25 73 20 67 6F 74 6F 20 3A 72 65 70 65 61 74 }
        $a2 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 5F }
    condition:
        all of them
}

rule Windows_Generic_Threat_3c4d9cbe {
    meta:
        id = "4deb07yJmOWshxVrwzl8ek"
        fingerprint = "v1_sha256_b32f9a3b86c60d4d69c59250ac59e93aee70ede890b059b13be999adbe043d2c"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "21d01bd53f43aa54f22786d7776c7bc90320ec6f7a6501b168790be46ff69632"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 53 56 57 8B 55 08 8B DA 8B 7A 3C 03 FA 66 81 3F 50 45 75 54 03 5F 78 8B 4B 18 8B 73 20 8B 7B 24 03 F2 03 FA FC 55 8B 6D 0C AD 03 C2 96 87 FD 51 33 C9 80 C1 0F F3 A6 72 0C 96 59 87 FD }
    condition:
        all of them
}

rule Windows_Generic_Threat_deb82e8c {
    meta:
        id = "5S9ZaAOEkXwl43hK3oqsvH"
        fingerprint = "v1_sha256_c24baecab39c72f6bb30713022297cb9fb41ef5339a353702f3f780a630d5b27"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0f5791588a9898a3db29326785d31b52b524c3097370f6aa28564473d353cd38"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 50 6F 76 65 72 74 79 20 69 73 20 74 68 65 20 70 61 72 65 6E 74 20 6F 66 20 63 72 69 6D 65 2E }
        $a2 = { 2D 20 53 79 73 74 65 6D 4C 61 79 6F 75 74 20 25 64 }
    condition:
        all of them
}

rule Windows_Generic_Threat_278c589e {
    meta:
        id = "7aK2shojF8qqtuVEUQy6rP"
        fingerprint = "v1_sha256_59bbbecd73541750f7221b12895ccf51e1a6863ceca62e23f541df904ad23587"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "cccc6c1bf15a7d5725981de950475e272c277bc3b9d266c5debf0fc698770355"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 49 6E 73 74 61 6C 6C 65 72 20 77 69 6C 6C 20 6E 6F 77 20 64 6F 77 6E 6C 6F 61 64 20 66 69 6C 65 73 20 72 65 71 75 69 72 65 64 20 66 6F 72 20 69 6E 73 74 61 6C 6C 61 74 69 6F 6E 2E }
    condition:
        all of them
}

rule Windows_Generic_Threat_6b621667 {
    meta:
        id = "6GBa9Hre5XEmitW2SzMfyS"
        fingerprint = "v1_sha256_3574b7ef24c4387a9919ed9831af7657047b26d8922ab78788619bbd3d0edd56"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b50b39e460ecd7633a42f0856359088de20512c932fc35af6531ff48c9fa638a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 64 A1 30 00 00 00 56 33 F6 89 75 FC 8B 40 10 39 70 08 7C 0F 8D 45 FC 50 E8 8F 0D 00 00 83 7D FC 01 74 03 33 F6 46 8B C6 5E C9 C3 8B FF 55 8B EC 51 51 53 56 6A 38 6A 40 E8 32 EB FF }
    condition:
        all of them
}

rule Windows_Generic_Threat_7693d7fd {
    meta:
        id = "1YY7vvBgUirvFqJ5Lx2u8Y"
        fingerprint = "v1_sha256_886ad084f33faf8baae8a650a88095757c2cff9e18c8f5c50ff36120b43ec082"
        version = "1.0"
        date = "2024-02-13"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fc40cc5d0bd3722126302f74ace414e6934eca3a8a5c63a11feada2130b34b89"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 51 8B 45 08 83 65 FC 00 8B 00 0F B7 48 14 66 83 78 06 00 8D 4C 01 18 0F 86 9A 00 00 00 53 56 57 8D 59 24 8B 13 8B CA 8B F2 C1 E9 1D C1 EE 1E 8B FA 83 E1 01 83 E6 01 C1 EF 1F F7 C2 }
    condition:
        all of them
}

rule Windows_Generic_Threat_df5de012 {
    meta:
        id = "3buIt5jxHGWNIRc3o02uKy"
        fingerprint = "v1_sha256_1a1ce3644c33a4591ab6582525366d47e07bdc2350aa6066ec5b5fedc605b037"
        version = "1.0"
        date = "2024-02-14"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "13c06d7b030a46c6bb6351f40184af9fafaf4c67b6a2627a45925dd17501d659"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 20 2C 3F 2C 2F 2C 37 2C 27 2C 3B 2C 2B 2C 33 2C 23 2C 3D 2C 2D 2C 35 2C 25 2C 39 2C 29 2C 31 2C 21 2C 3E 2C 2E 2C 36 2C 26 2C 3A 2C 2A 2C 32 2C 22 2C 3C 2C 2C 2C 34 2C 24 2C 38 2C 28 2C 30 2C 20 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0e8530f5 {
    meta:
        id = "5tS9UkGHuxUj0Jh8AExmVJ"
        fingerprint = "v1_sha256_f4a010366625c059151d3e704f6ece1808f367401729feaf6cc423cf4d5c5c60"
        version = "1.0"
        date = "2024-02-14"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9f44d9acf79ed4450195223a9da185c0b0e8a8ea661d365a3ddea38f2732e2b8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 63 6D 64 20 2F 63 20 73 74 61 72 74 20 22 22 20 22 25 53 25 53 22 20 25 53 }
        $a2 = { 76 68 61 50 20 71 20 65 71 30 75 61 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ba807e3e {
    meta:
        id = "6qga8jioLLjQ6LnRNN551u"
        fingerprint = "v1_sha256_896eedb949eec6dff3e867ae3179b741382dd25ba06c6db452ac1ae5bc6bc757"
        version = "1.0"
        date = "2024-02-14"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "cabd0633b37e6465ece334195ff4cc5c3f44cfe46211165efc07f4073aed1049"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 7D 4A 36 35 2B 7E 2E 2C 2F 37 2C 3D 31 7E 3B 3D 30 30 2F 2A 7E 3C 39 7E 2C 29 30 7E 35 30 7E 5A 4F 4B 7E 31 2F 3A 39 70 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4578ee8c {
    meta:
        id = "3Fx2xQgUBWUuTiZhwINaJ6"
        fingerprint = "v1_sha256_1a519bb84aae29057536ea09e53ff97cfe34a70c84ac6fa7d1ec173de3754f03"
        version = "1.0"
        date = "2024-02-14"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "699fecdb0bf27994d67492dc480f4ba1320acdd75e5881afbc5f73c982453fed"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 73 65 72 2D 41 67 65 6E 74 3A 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 25 64 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 25 64 2E 31 3B 20 53 56 31 29 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ebf62328 {
    meta:
        id = "4dvT8Q0gMCVoi9HomrGw8Y"
        fingerprint = "v1_sha256_e99b56dde761c5efad14f935befa4d1dbb31cd305b5d6af05a90d44dc3cd0098"
        version = "1.0"
        date = "2024-02-14"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "dfce19aa2e1a3e983c3bfb2e4bbd7617b96d57602d7a6da6fee7b282e354c9e1"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 74 52 75 50 5B 5D 5F 5E 41 5C 41 5D 41 5E }
        $a2 = { 5F 5E 41 5C 41 5E 41 5F 74 7A 75 78 }
        $a3 = { 44 64 71 52 71 77 7C 61 69 41 66 6E 68 73 6F 72 48 60 6C 65 49 46 }
    condition:
        all of them
}

rule Windows_Generic_Threat_dcc622a4 {
    meta:
        id = "1WRGHXShTcpA1sWqfwV1gI"
        fingerprint = "v1_sha256_9254226918f39389ccc347de1c5064552a8500ccef1884b8e27b6e98c651f45b"
        version = "1.0"
        date = "2024-02-14"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "94a3f10396c07783586070119becf0924de9a7caf449d6e07065837d54e6222d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5B 21 5D 20 45 72 72 6F 72 20 77 72 69 74 69 6E 67 20 73 68 65 6C 6C 63 6F 64 65 20 74 6F 20 74 68 65 20 74 61 72 67 65 74 20 64 72 69 76 65 72 2C 20 61 62 6F 72 74 }
    condition:
        all of them
}

rule Windows_Generic_Threat_046aa1ec {
    meta:
        id = "3yjzgtCooD7kt9RSl8cxpa"
        fingerprint = "v1_sha256_da6552da3db4851806f5a0ce3c324a79acf4ee4b2690cb02cc8d8c88a2ba28f8"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c74cf499fb9298d43a6e64930addb1f8a8d8336c796b9bc02ffc260684ec60a2"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 F4 D9 7D FE 66 8B 45 FE 80 CC 0C 66 89 45 FC D9 6D FC DF 7D F4 D9 6D FE 8B 45 F4 8B 55 F8 8B E5 5D C3 55 8B EC 51 33 D2 8D 5D 08 8B 03 83 C3 04 85 C0 74 03 03 50 04 49 75 F1 85 }
    condition:
        all of them
}

rule Windows_Generic_Threat_85c73807 {
    meta:
        id = "3Z5Gk7UwgGFg5pEKRGH5JZ"
        fingerprint = "v1_sha256_90aa64f17b91ccdf367e1976cd1f5e89e15c7369a58b2d19187143e70939d756"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7f560a22c1f7511518656ac30350229f7a6847d26e1b3857e283f7dcee2604a0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 56 57 89 4D FC 8B DA 8B F0 8B 7D 08 C6 86 18 01 00 00 00 8B C3 E8 15 01 00 00 84 C0 75 0E 8B 55 FC 8B C6 8B CF E8 45 F8 FF FF EB 0F 56 57 8B FE 8B F3 B9 47 00 00 00 F3 A5 5F 5E }
    condition:
        all of them
}

rule Windows_Generic_Threat_642df623 {
    meta:
        id = "5toKQRwEp2WKklqecGviNp"
        fingerprint = "v1_sha256_555eb66f117312fa4ff3a49c0c40f89caddec3eb4b93d11bda2cce40529d46a0"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e5ba85d1a6a54df38b5fa655703c3457783f4a4f71e178f83d8aac878d4847da"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 50 B8 04 00 00 00 81 C4 04 F0 FF FF 50 48 75 F6 8B 45 FC 81 C4 3C FE FF FF 53 56 57 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC 33 C9 8B 45 FC 89 45 DC 8B 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_27a2994f {
    meta:
        id = "5DW09p6quHGM01Gnl68awH"
        fingerprint = "v1_sha256_66f34ba3052e2369528aeaf076f10d58f8f3dca420666246e02191fecb057f8c"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e534914e06d90e119ce87f5abb446c57ec3473a29a7a9e7dc066fdc00dc68adc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 56 57 83 7D 08 00 75 05 E9 88 00 00 00 6A 09 E8 D7 FD FF FF 83 C4 04 8B 45 08 83 E8 20 89 45 FC 8B 4D FC 8B 51 14 81 E2 FF FF 00 00 83 FA 04 74 41 8B 45 FC 83 78 14 01 74 38 8B }
    condition:
        all of them
}

rule Windows_Generic_Threat_dbceec58 {
    meta:
        id = "283KGVvQTyhuLlbIMMb4NI"
        fingerprint = "v1_sha256_2a99fb7b342b43e3a4f0136d7d618625ca5708ae32e6fcabb11420bd8c89915b"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fbec30528e6f261aebf0d41f3cd6d35fcc937f1e20e1070f99b1b327f02b91e0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 14 83 7D 08 00 74 0C 83 7D 0C 00 74 06 83 7D 10 00 75 08 8B 45 08 E9 87 00 00 00 8B 45 08 89 45 FC 8B 45 0C 89 45 F8 8B 45 10 C1 E8 02 89 45 EC 83 65 F4 00 EB 07 8B 45 F4 40 89 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7407eb79 {
    meta:
        id = "13NGDMbAJoBzlK9qo7YRZF"
        fingerprint = "v1_sha256_a60c3e54493f9dab71584ba301c41c43f30d554df8c0b05674995faaf407ee48"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9ae0f053c8e2c4f4381eac8265170b79301d4a22ec1fdb86e5eb212c51a75d14"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 18 8B 45 08 8B 40 08 89 45 E8 8B 45 08 8B 40 0C 89 45 EC 8B 45 EC 83 C0 0C 89 45 F0 8B 45 F0 8B 00 89 45 F8 83 65 F4 00 E8 00 00 00 00 58 89 45 F4 8B 45 F8 3B 45 F0 74 31 8B 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_3613fa12 {
    meta:
        id = "3WiA2GUWmvrFXfiUfDq54B"
        fingerprint = "v1_sha256_77b23aaf384de138214e64342e170f3dce667ee41c3063c999286da9af6fff42"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1403ec99f262c964e3de133a10815e34d2f104b113b0197ab43c6b7b40b536c0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 89 4D FC 8D 45 08 50 8B 4D FC E8 4D 03 00 00 8B 45 FC 8B E5 5D C2 04 00 CC CC CC CC 55 8B EC 51 89 4D FC 8B 45 FC 8B E5 5D C3 CC CC 55 8B EC 51 89 4D FC 8B 45 08 50 8B 4D FC E8 FD }
    condition:
        all of them
}

rule Windows_Generic_Threat_b125fff2 {
    meta:
        id = "2d1y6NzQB63hz1DphcysCy"
        fingerprint = "v1_sha256_054f3f36c688e1f5c3116e7a926df12df90f79dc1d42bee2616b5251f6ad2c24"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "9c641c0c8c2fd8831ee4e3b29a2a65f070b54775e64821c50b8ccd387e602097"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6F 00 00 0A 6F 70 00 00 0A 00 28 24 00 00 06 0A 06 2C 24 00 28 1B 00 00 06 0B 07 2C 19 00 28 CE 04 00 06 16 FE 01 0C 08 2C 0B 7E 03 00 00 04 6F D3 04 00 06 00 00 00 28 1A 00 00 06 00 28 18 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d7e5ec2d {
    meta:
        id = "7fFH6MNjrfQI2QyBN4A2Oc"
        fingerprint = "v1_sha256_4edb8cc1da81e0b9b3a8facc9a9a7d1e27dff0d2db7851d06a209beec3ccb463"
        version = "1.0"
        date = "2024-02-20"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fe711664a565566cbc710d5e678a9a30063a2db151ebec226e2abcd24c0a7e68"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 F8 89 45 FC 8B 45 FC E8 17 FE FF FF 83 FA 00 75 03 83 F8 FF 77 16 8B 45 FC E8 F1 FE FF FF 83 FA 00 75 03 83 F8 FF 77 04 33 C0 EB 02 B0 01 88 45 FB 8A 45 FB 59 59 5D C3 8D 40 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_1636c2bf {
    meta:
        id = "4pxAhux5VcizqPEw68S8tH"
        fingerprint = "v1_sha256_c8b198cd5f9277ff3808ee2a313ab979d544b9e609d6623876d2e3c3c5668e38"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6e43916db43d8217214bbe4eb32ed3d82d0ac423cffc91d053a317a3dbe6dafb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 28 22 00 00 0A 80 19 00 00 04 28 3B 00 00 06 28 2D 00 00 0A 28 45 00 00 06 16 80 1D 00 00 04 7E 13 00 00 04 7E 15 00 00 04 16 7E 15 00 00 04 8E B7 16 14 FE 06 43 00 00 06 73 63 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_0a640296 {
    meta:
        id = "7IGJo2lm23LctjHhzcPAAt"
        fingerprint = "v1_sha256_743c47c7a58e7d65261818b4b444aaf8015b9b55d3e54526b1d63a8770a6c5aa"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3682eff62caaf2c90adef447d3ff48a3f9c34c571046f379d2eaf121976f1d07"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 02 7B 0F 00 00 04 6F 29 00 00 0A 7D 10 00 00 04 02 7B 10 00 00 04 28 2A 00 00 0A 00 02 7B 08 00 00 04 7B 03 00 00 04 02 7B 10 00 00 04 6F 2B 00 00 0A 16 FE 01 0D 09 39 29 01 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b1ef4828 {
    meta:
        id = "72zFiTXV4HkOd3Yttqlehr"
        fingerprint = "v1_sha256_d5d63f38308c6f8e5ca54567c7c8b93fcde69601fbcc28d56d5231edd28163cf"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "29b20ff8ebad05e4a33c925251d08824ca155f5d9fa72d6f9e359e6ec6c61279"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 70 36 72 20 74 24 76 28 78 2C 7A 30 7C 34 7E 38 7E 3C 7E 40 7E 54 7E 74 7E 7C 5D }
        $a2 = { 7E 30 7E 34 7E 43 7E 4F 7E 5A 7E 6E 7E 79 7E }
    condition:
        all of them
}

rule Windows_Generic_Threat_48cbdc20 {
    meta:
        id = "41LjUDYvngeh9nqQTi59KP"
        fingerprint = "v1_sha256_687d0f3dc85a7e4b23019deec59ee77c211101d40ed6622a952e69ebc4151483"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7a7704c64e64d3a1f76fc718d5b5a5e3d46beeeb62f0493f22e50865ddf66594"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5E 69 69 69 4E 42 42 42 3E 2E 2E 2E 25 }
        $a2 = { 24 2E 2E 2E 2F 41 41 41 3A 51 51 51 47 5D 5D 5D 54 69 69 69 62 }
    condition:
        all of them
}

rule Windows_Generic_Threat_420e1cdc {
    meta:
        id = "5X3DmGmlOnB8r867J33IIA"
        fingerprint = "v1_sha256_6bd8a7bd4392e04d64f2e0b93d80978f59f9af634a0c971ca61cb9cb593743e0"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b20254e03f7f1e79fec51d614ee0cfe0cb87432f3a53cf98cf8c047c13e2d774"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 56 8B 75 08 85 F6 74 5A ?? ?? ?? ?? ?? 83 F8 03 75 16 56 E8 ED 01 00 00 59 85 C0 56 74 36 50 E8 0C 02 00 00 59 59 EB 3A 83 F8 02 75 26 8D 45 08 50 8D 45 FC 50 56 E8 25 0F 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4c37e16e {
    meta:
        id = "6thgnHsKTToDOqWcM35vTl"
        fingerprint = "v1_sha256_dabac8aa6a3f4d4bd726161fc6573ca9de4088e7d818c3cf33cafc91f680e7aa"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d83a8ed5e192b3fe9d74f3a9966fa094d23676c7e6586c9240d97c252b8e4e74"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 2E 3F 41 56 43 44 72 6F 70 41 70 69 40 40 }
        $a2 = { 2D 2D 77 77 6A 61 75 67 68 61 6C 76 6E 63 6A 77 69 61 6A 73 2D 2D }
    condition:
        all of them
}

rule Windows_Generic_Threat_5be3a474 {
    meta:
        id = "4gYGYuiPPidSLM2IlT2VY8"
        fingerprint = "v1_sha256_0f0f46e3bdebb47a4f43ccb64d65ab1e15d68d38c117cb25e5723ec16e7e0758"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b902954d634307260d5bd8fb6248271f933c1cbc649aa2073bf05e79c1aedb66"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 56 57 8B F9 33 F6 8D 5F 02 66 8B 07 83 C7 02 66 3B C6 75 F5 8A 01 2B FB D1 FF 8D 5F FF 85 DB 7E 23 0F B6 F8 83 C1 02 66 8B 01 8D 49 02 66 2B C7 C7 45 FC 00 08 00 00 66 2B 45 FC }
    condition:
        all of them
}

rule Windows_Generic_Threat_b191061e {
    meta:
        id = "71yF7Nsnzv4fNW39agmaiw"
        fingerprint = "v1_sha256_cbee10eab984249ceb9f8a82dc06aa014d6a249321f3d4f0d1e5657aab205ec8"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bd4ef6fae7f29def8e5894bf05057653248f009422de85c1e425d04a0b2df258"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 2C 64 A1 30 00 00 00 33 D2 53 56 57 8B 40 0C 8B F2 89 4D E8 89 55 F4 89 75 F8 8B 58 0C 8B 7B 18 89 7D F0 85 FF 0F 84 34 01 00 00 C7 45 E0 60 00 00 00 8B 43 30 89 55 FC 89 55 EC }
    condition:
        all of them
}

rule Windows_Generic_Threat_05f52e4d {
    meta:
        id = "1v6adYooB9FBgXHUzm1Qsy"
        fingerprint = "v1_sha256_79898b59b6d3564aad85d823a1450600faff5b1d2dbfbe0cee4cc59971e4f542"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e578b795f8ed77c1057d8e6b827f7426fd4881f02949bfc83bcad11fa7eb2403"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 06 73 45 00 00 0A 73 46 00 00 0A 6F 47 00 00 0A 14 FE 06 29 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0B 14 FE 06 2A 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0C 07 6F 47 00 00 0A 08 6F 47 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c34e19e9 {
    meta:
        id = "5MTleXQye9B4fo3hq0wZCV"
        fingerprint = "v1_sha256_87999b6f2cf359b6436ee7e57691ac73fc41f3947bf8fef3f6b98148e17f180d"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f9048348a59d9f824b45b16b1fdba9bfeda513aa9fbe671442f84b81679232db"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 73 18 00 00 0A 7E 02 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 8E 69 6F 29 00 00 0A 9A 0A 7E 01 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 73 18 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_e691eaa1 {
    meta:
        id = "HKQ8ocRPaJ4vWXcJSvlgC"
        fingerprint = "v1_sha256_0ac310e3f7cf99b77c2dcfea582752e2f1414caf43965c25d2f3f03cf27586cc"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "afa5f36860e69b9134b93e9ad32fed0a5923772e701437e1054ea98e76f28a77"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 8B C2 53 89 45 FC 8B D9 56 99 33 F6 2B C2 57 8B F8 D1 FF 85 FF 7E 2B 8B 55 FC 4A 03 D3 0F B6 02 8D 52 FF 8A 0C 1E ?? ?? ?? ?? ?? ?? ?? 88 04 1E 46 0F B6 C1 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5e33bb4b {
    meta:
        id = "1DPVh84gCnmyfCtJLRlloR"
        fingerprint = "v1_sha256_7e2002c3917ccab7d9f56a7aa20ea75be71aa7fdc64b7c3f87edb68be38e74b2"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "13c06d7b030a46c6bb6351f40184af9fafaf4c67b6a2627a45925dd17501d659"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 43 3A 5C 55 73 65 72 73 5C 61 64 6D 69 6E 5C 44 65 73 6B 74 6F 70 5C 57 6F 72 6B 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 5C 52 65 6C 65 61 73 65 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 2E 70 64 62 }
    condition:
        all of them
}

rule Windows_Generic_Threat_be64ba10 {
    meta:
        id = "8gV7YsqJT11siVIfgdEnl"
        fingerprint = "v1_sha256_c6acce53610baf119a0e2d55fc698a976463bbd21b739d4ac39a75383fa5fed2"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "24bb4fc117aa57fd170e878263973a392d094c94d3a5f651fad7528d5d73b58a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 22 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 22 3A 22 28 2E 2B 3F 29 22 }
        $a2 = { 2E 3F 41 56 3C 6C 61 6D 62 64 61 5F 37 65 66 38 63 66 32 36 39 61 32 32 38 62 36 30 34 64 36 35 34 33 32 65 37 65 63 33 37 30 31 34 3E 40 40 }
    condition:
        all of them
}

rule Windows_Generic_Threat_7bb75582 {
    meta:
        id = "3f2NBUde69t33XukNAli2g"
        fingerprint = "v1_sha256_d959f755d28782b332248085034950a8d4cad3cde13b22254c90ca3952919e1b"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "35f9698e9b9f611b3dd92466f18f97f4a8b4506ed6f10d4ac84303177f43522d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 4B 45 59 5F 43 55 52 52 45 4E 54 5F 55 53 45 52 5C 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 49 6E 74 65 72 6E 65 74 20 53 65 74 74 69 6E 67 73 5C 43 6F 6E 6E 65 63 74 69 6F 6E 73 20 5B 31 20 37 20 31 37 5D }
    condition:
        all of them
}

rule Windows_Generic_Threat_59698796 {
    meta:
        id = "11tKOHhllJ7iJoEjTRb5O0"
        fingerprint = "v1_sha256_59569049dbb09b7e15110fb8de1a146eb7fd606f116b4dd6c75ca973fb62296e"
        version = "1.0"
        date = "2024-03-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "35f9698e9b9f611b3dd92466f18f97f4a8b4506ed6f10d4ac84303177f43522d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 81 EC B8 04 00 00 ?? ?? ?? ?? ?? 33 C5 89 45 FC 56 68 00 04 00 00 0F 57 C0 C7 45 F8 00 00 00 00 8D 85 58 FB FF FF C7 85 54 FB FF FF 24 00 00 00 6A 00 50 8B F1 0F 11 45 D8 0F 11 45 E8 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2ae9b09e {
    meta:
        id = "4DzSgxGWhrOQ3lk0ijCBGg"
        fingerprint = "v1_sha256_183249214e5f8143eb91caf20778b870d17d7a52b6d71ad603827e8716e7e447"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "dc8f4784c368676cd411b7d618407c416d9e56d116dd3cd17c3f750e6cb60c40"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 51 8B 45 08 89 45 FC 8B 45 0C 89 45 F8 8B 45 0C 48 89 45 0C 83 7D F8 00 76 0F 8B 45 FC C6 00 00 8B 45 FC 40 89 45 FC EB DE 8B 45 08 C9 C3 6A 41 5A 0F B7 C1 66 3B D1 77 0C 66 83 F9 }
    condition:
        all of them
}

rule Windows_Generic_Threat_604a8763 {
    meta:
        id = "GCLxn2ltt753DymZtNNgZ"
        fingerprint = "v1_sha256_cf88c0d102680fc7c16d49b6e8dc49c16b27d5940edf078e667a45e70ebe3883"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "2a51fb11032ec011448184a4f2837d05638a7673d16dcf5dcf4005de3f87883a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 8B 45 0C 48 89 45 FC EB 07 8B 45 FC 48 89 45 FC 83 7D FC 00 7C 0B 8B 45 08 03 45 FC C6 00 00 EB E8 C9 C3 55 8B EC 83 EC 0C 8B 45 0C 89 45 FC 8B 45 08 3B 45 10 76 2F 8B 45 FC 89 45 }
    condition:
        all of them
}

rule Windows_Generic_Threat_f45b3f09 {
    meta:
        id = "4phSkBpK68awy8NeHCqCsH"
        fingerprint = "v1_sha256_9b01ad1271cc5052a793e5a885aa7289cbaea4a928f60d64194477c3036496ed"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "577f1dbd76030c7e44ed28c748551691d446e268189af94e1fa1545f06395178"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 33 ED 44 8B ED 48 89 6C 24 78 44 8B FD 48 89 AC 24 88 00 00 00 44 8B F5 44 8B E5 E8 43 04 00 00 48 8B F8 8D 75 01 ?? ?? ?? ?? ?? 66 39 07 75 1A 48 63 47 3C 48 8D 48 C0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_3f390999 {
    meta:
        id = "6nkVVd4rSICiFmsATVN6R3"
        fingerprint = "v1_sha256_462a7a38ebbb39515ac2c0a10353660d0cadcfb99360adcd200edc1db5a716ba"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "1b6fc4eaef3515058f85551e7e5dffb68b9a0550cd7f9ebcbac158dac9ababf1"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 10 48 89 D9 48 8B 59 10 FF 61 08 0F 1F 40 00 49 89 CB C3 49 89 CA 41 8B 43 08 41 FF 23 C3 90 48 C1 E1 04 31 C0 81 E1 F0 0F 00 00 49 01 C8 4C 8D 0C 02 4E 8D 14 00 31 C9 45 8A 1C 0A 48 }
    condition:
        all of them
}

rule Windows_Generic_Threat_abd1c09d {
    meta:
        id = "2gAiGqVivGKrgyriswmPLZ"
        fingerprint = "v1_sha256_80e6f317e5cd91cb3819e9251efc8c96218071bec577a38c8784826dd4a657cb"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "3ff09d2352c2163465d8c86f94baa25ba85c35698a5e3fbc52bc95afc06b7e85"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 0C 8B D1 53 56 57 8B 7D 0C 83 FF 08 77 1A 85 FF 74 16 8B 5D 08 8B 4A 14 8B 72 10 2B CE 8D 04 3B 3B C1 72 11 C6 42 44 00 33 C0 33 D2 5F 5E 5B 8B E5 5D C2 08 00 0F 57 C0 66 0F 13 }
    condition:
        all of them
}

rule Windows_Generic_Threat_b7870213 {
    meta:
        id = "6qFBxHKyJ4i1zqncQgxhAJ"
        fingerprint = "v1_sha256_79b8385543def42259cd9c09d4d7059ff6bb02a9e87cff1bc0a8861e3b333c5f"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "04cb0d5eecea673acc575e54439398cc00e78cc54d8f43c4b9bc353e4fc4430d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 75 28 6B 6E 4E 30 30 30 31 30 32 30 33 30 34 30 35 30 36 30 37 30 38 30 39 31 30 31 31 31 32 31 33 31 34 31 35 31 36 31 37 31 38 31 39 32 30 32 31 32 32 32 33 32 34 32 35 32 36 32 37 32 38 32 39 33 30 33 31 33 32 33 33 33 34 33 35 33 36 33 37 33 38 33 39 34 30 34 31 34 32 34 33 34 34 34 35 34 36 34 37 34 38 34 39 35 30 35 31 35 32 35 33 35 34 35 35 35 36 35 37 35 38 35 39 36 30 36 31 36 32 36 33 36 34 36 35 36 36 36 37 36 38 36 39 37 30 37 31 37 32 37 33 37 34 37 35 37 36 37 37 37 38 37 39 38 30 38 31 38 32 38 33 38 34 38 35 38 36 38 37 38 38 38 39 39 30 39 31 39 32 39 33 39 34 39 35 39 36 39 37 39 38 39 39 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2bba6bae {
    meta:
        id = "2O5AGVgyoWhhin0XTncK1z"
        fingerprint = "v1_sha256_59e4b173c21b0ab161adf8d89f253f21403bca706b6bf40b3da00697f87dd509"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d9955c716371422750b77d64256dade6fbd028c8d965db05c0d889d953480373"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 36 35 20 37 39 20 34 31 20 36 39 20 36 34 20 34 38 20 36 43 20 37 37 20 34 39 20 36 41 20 36 46 20 36 37 20 34 39 20 36 42 20 37 30 20 35 38 20 35 36 20 34 33 20 34 39 20 37 33 20 34 39 20 34 33 20 34 41 20 36 38 20 36 32 20 34 37 20 36 33 20 36 39 20 34 46 20 36 39 20 34 31 20 36 39 20 35 32 20 35 37 20 35 32 20 34 35 20 35 35 20 33 30 20 34 35 20 36 39 20 34 39 20 34 38 20 33 30 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4db75701 {
    meta:
        id = "3oVCYoTYshwCFGA9HB9EHF"
        fingerprint = "v1_sha256_65f7d15ed551e069b30ce6c0a5f15d01d24b8b29727950269c9956fcf6dc799d"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "fa7847d21d5a350cf96d7ecbcf13dce63e6a0937971cfb479700c5b31850bba9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 81 EC D0 02 00 00 80 79 20 08 41 8B F1 45 8B F0 4C 8B FA 48 8B F9 0F 84 3A 01 00 00 48 89 58 10 48 89 68 18 43 8D 04 40 48 63 C8 ?? ?? ?? ?? ?? 48 8D 8C 24 20 02 00 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_54a914c9 {
    meta:
        id = "566ehahY7DtXROZ8MsLz2V"
        fingerprint = "v1_sha256_0cc3797564b4c722423f915493e07b0e0fec3085e7a535f9914f82d73c797bed"
        version = "1.0"
        date = "2024-03-25"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c418c5ad8030985bb5067cda61caba3b7a0d24cb8d3f93fc09d452fbdf4174ec"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 20 48 89 CB 48 8B 43 08 4C 8B 48 30 4D 85 C9 74 16 48 8D 4B 10 0F B6 D2 48 83 C4 20 5B 5E 5F 5D 41 5C 49 FF E1 66 90 44 0F B6 40 10 41 80 F8 16 0F 84 81 00 00 00 41 80 F8 18 74 0B 48 }
    condition:
        all of them
}

rule Windows_Generic_Threat_38a88967 {
    meta:
        id = "3zOduFz7oSfQ9mtV0AEUrM"
        fingerprint = "v1_sha256_ddbdb1c39a07141d83173504214c889aff75487570d906413ebc6f262fedf9ae"
        version = "1.0"
        date = "2024-03-25"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "6e425eb1a27c4337f05d12992e33fe0047e30259380002797639d51ef9509739"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 60 E8 00 00 00 00 5B ?? ?? ?? ?? ?? ?? 8B 75 08 8B 7D 0C AD 50 53 89 C1 29 DB 29 C0 AC C1 E3 04 01 C3 AA 89 D8 ?? ?? ?? ?? ?? 85 C0 74 07 89 C2 C1 EA 18 31 D3 F7 D0 21 C3 E2 DF 87 DA }
    condition:
        all of them
}

rule Windows_Generic_Threat_e8abb835 {
    meta:
        id = "7GHd1IZK92CrQQRxw3rvBS"
        fingerprint = "v1_sha256_0ad56b8c741a79a600a0d5588c4e8760a6d19fef72ff7814a00cfb84a90f23aa"
        version = "1.0"
        date = "2024-03-26"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "e42262671325bec300afa722cefb584e477c3f2782c8d4c6402d6863df348cac"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 81 EC 28 05 00 00 66 44 0F 7F 84 24 10 05 00 00 66 0F 7F BC 24 00 05 00 00 0F 29 B4 24 F0 04 00 00 44 89 44 24 74 48 89 94 24 C8 00 00 00 48 89 CB 48 C7 44 24 78 00 00 00 00 0F 57 F6 0F 29 }
    condition:
        all of them
}

rule Windows_Generic_Threat_492d7223 {
    meta:
        id = "islI9r7Z7kGJGcKHUlXuc"
        fingerprint = "v1_sha256_9fb2a00def86ed8476d906514a0bc630e28093ac37d757541d8801d2c8e0efc3"
        version = "1.0"
        date = "2024-03-26"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "c0d9c9297836aceb4400bcb0877d1df90ca387f18f735de195852a909c67b7ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 53 57 56 83 EC 24 ?? ?? ?? ?? ?? 31 C9 85 C0 0F 94 C1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 C8 40 FF E0 }
    condition:
        all of them
}

rule Windows_Generic_Threat_ea296356 {
    meta:
        id = "6PqmYLGQARLLEVxUK9swwb"
        fingerprint = "v1_sha256_73ffd16f0047cd57311853aa9083fc21427f2eb21646c6edc7b8def86da90f90"
        version = "1.0"
        date = "2024-05-22"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "4c48a0fe90f3da7bfdd32961da7771a0124b77e1ac1910168020babe8143e959"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 83 EC 0C 53 56 8B 75 08 8B C6 89 55 FC 99 2B C2 89 4D F8 8B D8 8B 45 FC 57 D1 FB 33 FF 8D 14 30 89 55 08 85 DB 7E 36 4A 0F 1F 44 00 00 8A 0C 38 8D 52 FF 0F B6 42 01 8B 75 FC 0F B6 80 }
    condition:
        all of them
}

rule Windows_Generic_Threat_aeaeb5cf {
    meta:
        id = "4RK5ibOpvYOfrv0yI8DUDv"
        fingerprint = "v1_sha256_640966296bad70234e0fe7b6f87b92fcf4fc111189d307d44f32e926785f76cb"
        version = "1.0"
        date = "2024-05-22"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f57d955d485904f0c729acff9db1de9cb42f32af993393d58538f07fa273b431"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 8B 4D 08 33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8D 04 45 02 00 00 00 50 FF 75 0C 51 ?? ?? ?? ?? ?? 83 C4 0C 5D C3 CC CC 55 8B EC 6A 00 FF 75 08 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c8424507 {
    meta:
        id = "LB17eQByeuzwvp5an4enq"
        fingerprint = "v1_sha256_78d56257cb6e1d67f9343ee30b844fe20138e27ca3b6312a07112e5dbb797851"
        version = "1.0"
        date = "2024-05-22"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "d556b02733385b823cfe4db7e562e90aa520e2e6fb00fceb76cc0a6a1ff47692"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 78 75 73 65 68 6F 62 69 6D 6F 7A 61 63 6F 67 6F 6A 69 68 6F 67 69 76 6F }
        $a2 = { 62 65 6D 69 74 69 76 65 67 69 77 6F 6D 65 7A 75 76 65 62 61 67 }
    condition:
        all of them
}

rule Windows_Generic_Threat_9af87ddb {
    meta:
        id = "57YANLQ5JUSpp0DVdWJzUV"
        fingerprint = "v1_sha256_99174c5740324d7704a5c6ae924254f9b5f241c97901dfdb771fc176a76e4a30"
        version = "1.0"
        date = "2024-05-23"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "b1fbc11744e21dc08599412887a3a966572614ce25ccd3c8c98f04bcbdda3898"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 28 2C 00 00 06 11 06 17 D6 13 06 11 06 11 07 8E B7 32 98 06 17 D6 0A 20 E8 03 00 00 28 21 00 00 0A 7E 0F 00 00 04 3A 74 FF FF FF 2A 00 1B 30 04 00 96 00 00 00 1F 00 00 11 03 39 88 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d7b57912 {
    meta:
        id = "7hFUmRmfHYsXdRpTqmGr9u"
        fingerprint = "v1_sha256_a774e3030d81e29805a9784cfbbc0b69c4fedebe0daa25e403777e1f46f9094f"
        version = "1.0"
        date = "2024-05-23"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0906599be152dd598c7f540498c44cc38efe9ea976731da05137ee6520288fe4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 83 C4 B8 53 56 8B DA 89 45 FC 8D 45 FC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8B C3 ?? ?? ?? ?? ?? 6A 00 6A 00 8D 45 F0 50 8B 45 FC }
    condition:
        all of them
}

rule Windows_Generic_Threat_23d33b48 {
    meta:
        id = "3Bo9ywWSszSWwQz5hipmfc"
        fingerprint = "v1_sha256_c9fb93bb74e4d45197d0da5b641860738a42a583b15cc098e86ea79bb8690bf7"
        version = "1.0"
        date = "2024-06-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "acbc22df07888498ae6f52f5458e3fb8e0682e443a8c2bc97177a0320b4e2098"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 83 7A 14 10 8B C2 53 56 57 8B F1 72 02 8B 02 83 7E 14 10 72 02 8B 0E 8B 5A 10 8D 56 10 8B 3A 53 50 89 55 FC 8B D7 51 ?? ?? ?? ?? ?? 8B D0 83 C4 0C 83 FA FF 74 30 3B FA 72 33 8B C7 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4b0b73ce {
    meta:
        id = "3shTt5MrUnIActpuvXVMQe"
        fingerprint = "v1_sha256_d53923df612dd7fe0b1b2c94c1c5d747b08723df129089326ec27c5049769cef"
        version = "1.0"
        date = "2024-06-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "236fc00cd7c75f70904239935ab90f51b03ff347798f56cec1bdd73a286b24c1"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 56 57 8B 7D 08 83 7F 18 00 C6 45 FF C9 74 54 ?? ?? ?? ?? ?? ?? 8D 9B 00 00 00 00 33 F6 83 7F 18 00 74 40 6A 0A FF D3 46 81 FE E8 03 00 00 7C ED 8B 07 8B 50 08 6A 01 8D 4D FF 51 }
    condition:
        all of them
}

rule Windows_Generic_Threat_1f2e969c {
    meta:
        id = "2PrvUAp65DxDAd6W1XpgrA"
        fingerprint = "v1_sha256_7d984a902f9bf40c9b49da89aba9249f80b41b24ca1cdb6189f541b40ef41742"
        version = "1.0"
        date = "2024-06-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "7def75df729ed66511fbe91eadf15bc69a03618e78c48e27c35497db2a6a97ae"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 53 8B 5A 10 56 8B F1 57 6A 78 89 75 FC C7 46 10 00 00 00 00 C7 46 14 0F 00 00 00 53 89 75 FC C6 06 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 33 C0 89 7D FC 85 DB 7E 39 0F 1F 40 00 }
    condition:
        all of them
}

rule Windows_Generic_Threat_27c975fd {
    meta:
        id = "wB3acaTOqGp52Cb2eawzQ"
        fingerprint = "v1_sha256_f4c500331ce0857b17970206fae4f8501c6f3a65824f37b6cdde47d0a03ceb78"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0108af363959f90919f24220caf426fba50be3d61f3735bb0f2acbbcc1f56e0c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 83 6D 0C 01 75 1B FF 75 08 ?? ?? ?? ?? ?? ?? 33 C0 50 50 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 40 5D C2 0C 00 55 8B EC 83 EC 10 ?? ?? ?? ?? ?? 33 C5 89 45 FC 53 8B D9 }
    condition:
        all of them
}

rule Windows_Generic_Threat_d170474c {
    meta:
        id = "7FP61SstN3WV8EHcGzfYQh"
        fingerprint = "v1_sha256_45089557acec0549acc3f5856c4eef89543ed048984474718376a73085edcb08"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "63da7ea6d4cd240485ad5c546dd60b90cb98d6f4f18df4bc708f5ec689be952f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 02 00 06 6F 36 03 00 06 11 00 28 DC 00 00 06 02 03 11 00 73 7E 00 00 06 13 01 7E 64 00 00 04 13 0F 16 13 03 11 03 11 0F 8E 69 2F 22 11 0F 11 03 9A 13 04 11 04 12 01 6F 83 00 00 06 DE 08 13 }
    condition:
        all of them
}

rule Windows_Generic_Threat_f57e5e2a {
    meta:
        id = "5K8h8t50LujkNVXEcuSogi"
        fingerprint = "v1_sha256_ce972e45f87792599b0800883e848221b0c2c99c9a0432659c655903f530e852"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "bff5112830cc3547c206fb1d028c592a11a3c7cd457ef445b765af86a1e76001"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 56 57 8B 75 08 8B 4D 0C E8 00 00 00 00 58 83 C0 2A 83 EC 08 89 E2 C7 42 04 33 00 00 00 89 02 E8 0E 00 00 00 66 8C D9 8E D1 83 C4 14 5F 5E 5D C2 08 00 8B 3C 24 FF 2A 48 31 C0 57 FF D6 }
    condition:
        all of them
}

rule Windows_Generic_Threat_4fe0deb6 {
    meta:
        id = "7Fnectj4k8qOq0vVlnaT3R"
        fingerprint = "v1_sha256_7737c264c98a0256c0a0075ab6b2e9525550e0ef60fd64a6c50cf8075639e96c"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "5836ef66985e851b37a369b04cce579afdb3b241d46a096bf8b1e8d4df053cd2"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC DD 45 08 B9 00 00 F0 7F D9 E1 B8 00 00 F0 FF 39 4D 14 75 3B 83 7D 10 00 75 75 D9 E8 D8 D1 DF E0 F6 C4 05 7A 0F DD D9 DD D8 DD 05 A8 B7 44 00 E9 E9 00 00 00 D8 D1 DF E0 DD D9 F6 C4 41 }
    condition:
        all of them
}

rule Windows_Generic_Threat_c9003b7b {
    meta:
        id = "3wOB7FWIzmZyuOg8fGDhcQ"
        fingerprint = "v1_sha256_deac86398c04c462d4aa3361c911acec99d422e2ce995ba82fc3e8fe9772c33b"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ff2a1def8c4fae4166e249edab62d73f44ba3c05d5e3c9fda11399bfe1fcee6c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 81 EC B8 01 00 00 49 89 CE 4C 8B 41 28 48 8B 51 48 E8 FE FE FF FF 48 89 C6 4D 8B 46 28 49 8B 56 50 4C 89 F1 E8 EB FE FF FF 48 89 C7 4D 8B 46 28 49 8B 96 E8 01 00 00 4C 89 F1 E8 D5 FE FF FF }
    condition:
        all of them
}

rule Windows_Generic_Threat_21253888 {
    meta:
        id = "4e01nO59ZIsnXhKaHBLGOu"
        fingerprint = "v1_sha256_121fc74ff09ebd9f2d6eda370b6fa6b5137e0ae59cf6d6f8f18d13e1cc053e15"
        version = "1.0"
        date = "2024-10-11"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "95e523f4003a10a906ef7c68a258d402e25f235fa9f2b022faff7cae41185b9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 24 34 30 33 61 64 63 37 61 2D 39 64 34 64 2D 34 64 37 39 2D 38 63 34 38 2D 36 36 31 61 64 63 66 66 37 33 65 35 }
    condition:
        all of them
}

rule Windows_Generic_Threat_06dcb833 {
    meta:
        id = "6y0Y0aFoaKquuUDtKBwzqz"
        fingerprint = "v1_sha256_cbddf2b858278ad4a9330dac767f0a0bc7691cbf6a93ac389f48cb2286c8cbdc"
        version = "1.0"
        date = "2024-10-11"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f7fde85aefb7123ef805c85394907ef73e0983499b49f2290a83aa2b0a2e5e9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 81 EC 04 36 00 00 B8 75 00 00 00 66 89 85 0C DA FF FF B9 73 00 00 00 66 89 8D 0E DA FF FF BA 65 00 00 00 66 89 95 10 DA FF FF B8 72 00 00 00 66 89 85 12 DA FF FF B9 33 00 00 00 66 89 }
    condition:
        all of them
}

rule Windows_Generic_Threat_5435fe36 {
    meta:
        id = "3AdK7x1W2oFU8IM1vfZFNU"
        fingerprint = "v1_sha256_7295e8addf2dcd6192eab261d7a2ca817006a3962dd2e792f51154495be54298"
        version = "1.0"
        date = "2024-10-11"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "8c0e26af4f9c783844ea457c3eb7bb2bbe1bf3f860ce180bacab00456f3ae7c1"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 83 EC 18 C7 45 F0 00 00 00 00 64 A1 30 00 00 00 89 45 EC C7 45 FC 00 00 00 00 8B 4D EC 8B 51 0C 8B 42 14 89 45 F4 8B 4D F4 89 4D F8 EB 08 8B 55 F8 8B 02 89 45 F8 8B 4D F4 8B 55 F8 3B }
    condition:
        all of them
}

rule Windows_Generic_Threat_491a8310 {
    meta:
        id = "3vRmS58KRn2YapxlwXKVba"
        fingerprint = "v1_sha256_45b1017a7ba8d5dc321ac018613587c371380a3340f6893a046a6bdc8a1d2431"
        version = "1.0"
        date = "2024-10-11"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "59c6846b4676378d9c80d7ced825f0463d1b333546bfcad919ee262cbf6db250"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 8B 45 0C 83 E8 02 74 21 2D 10 01 00 00 75 23 8B 45 14 50 8B 45 10 50 8B 45 0C 50 8B 45 08 50 ?? ?? ?? ?? ?? 89 45 FC EB 28 6A 00 ?? ?? ?? ?? ?? EB 1A 8B 45 14 50 8B 45 10 50 }
    condition:
        all of them
}

rule Windows_Generic_Threat_2f726f2d {
    meta:
        id = "19zfGGKDyXNXmQjtOa7PDe"
        fingerprint = "v1_sha256_41314d0685f957a3cdfa37f8f2275ab19137da289c57069b8d3a3e40e4b802e7"
        version = "1.0"
        date = "2024-10-11"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "ede9bd928a216c9844f290be0de6985ed54dceaff041906dca3a3468293464b6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 83 EC 0C 89 4D F8 8B 45 F8 83 78 08 00 75 04 32 C0 EB 26 ?? ?? ?? ?? ?? ?? 89 4D F4 6A 00 8B 55 F8 8B 42 08 50 FF 55 F4 85 C0 74 06 C6 45 FF 01 EB 04 C6 45 FF 00 8A 45 FF 8B E5 5D C3 }
    condition:
        all of them
}

