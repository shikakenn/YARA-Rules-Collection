rule Windows_Generic_MalCert_ec4381c9 {
    meta:
        id = "7BbNGnTFsJYH3akGXXS2RL"
        fingerprint = "v1_sha256_bd365f9aada0fcdba224367efa895f251371f1c2a45d7fb23cb120023bbaa732"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6b0ce8e6ccab57ece76302b1c9ab570336f63bae4d11137ccf0b662fa323a457"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 4D 60 69 B5 05 25 63 39 49 C1 2B 22 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_024569d4 {
    meta:
        id = "2UVIzEPalJ25ivXAYRaaGb"
        fingerprint = "v1_sha256_f2afbeb44a19ec7fd6a644157acaaf8dcdf277b09937eab160f7e140e6d076fb"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "fa3614bbfbe3ccdee5262a4ad0ae4808cb0e689cde22eddaf30dd8eb23b0440b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 25 06 C0 C5 BA 74 E2 F6 01 FD 8F D8 F4 4B 79 A1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_871164db {
    meta:
        id = "4kp4mLTEWXKiNAKLzfTtw0"
        fingerprint = "v1_sha256_edaec922a5aa4d64c744c02f453e521725c4d2ec5f9130147101be8398108b6a"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2ef886a8a67509d25708026b2ea18ce3f6e5a2fecd7b43a900e43dddab9a7935"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 0B 35 60 46 7C 36 DE 7E 94 29 E0 A9 78 2D B2 D6 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_101ac60e {
    meta:
        id = "4n0yj0TnEb7iwRuBXgGybK"
        fingerprint = "v1_sha256_e66b25dbc0325918c0ec4ebec49290d5ac6c1fddafbdc33c338186d3afbcade9"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "05c02be58b84139a25c8cd8662efd3a377765a0d69ab206aa6b17e22904ebc9e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 77 28 6A 4C BB 8C 2A D8 CD E8 4A AD }
    condition:
        all of them
}

rule Windows_Generic_MalCert_abeefc63 {
    meta:
        id = "57Z3uEg5rB3i94SCINYQM7"
        fingerprint = "v1_sha256_442c6692f2da75b823ba464bd063d66859b22a096ca210737666352f34c0a5a4"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c070b4fefefe4d3fdce930166f65a43b788eaf24e53bd67d301d920a5c594462"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 41 85 CF D1 37 F9 9E A0 EB 45 46 54 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_234b63fb {
    meta:
        id = "211CeKlRZHM5A74vV7uZvf"
        fingerprint = "v1_sha256_e62673f7a8bdb403d8b0f9b79cb99146e41715d77972e5ba315d3fd0912edda9"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "bd699b1213d86f2d1d35f79bd74319d24df1c77cdef5c010720dfb290d0c74f2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 51 E1 5E FC 91 6D A7 06 BF E8 47 36 6E 5C AF CB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ab8661e1 {
    meta:
        id = "3qvcVEiNty43ACRGmjFqVV"
        fingerprint = "v1_sha256_a29b2850de7529783a757176711d0b61d8ae17918cc35f8cc12efcdd0cea0e78"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5b7aefe3a61be8dbc94b2f8f75ad479a93a04078f0f0b45ba6c86ab7eb12f911"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 08 2B DD E2 74 00 8D CD FF 05 BA 08 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_6926a408 {
    meta:
        id = "5ZanqXYO1eUJfTy0Zs1brz"
        fingerprint = "v1_sha256_c6c5a7a54d4a1db10389c5d51fc653b96de3464d2651dec13f93164136b3f0a0"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "737916b4a5c2efd460eb4bf84dc4d01d505f1c0779a984e5471b2bc71582a545"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 50 57 28 6E 40 33 FC B0 00 00 00 00 55 65 F5 AC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ff00d21d {
    meta:
        id = "3IvzoCjGWdh1Mpucd5Qnpw"
        fingerprint = "v1_sha256_0e3a9f9208d5a967013cfda84772ebdf8a77d10800e99f234527c9b25182e823"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f275e6b5ded3553648a1f231cd4079d30186583be0edeca734b639073ae53854"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 04 4C 17 7A 97 }
        $a2 = "Netgear Inc."
    condition:
        all of them
}

rule Windows_Generic_MalCert_f20eba4e {
    meta:
        id = "asO30wcS45m200xADYMmb"
        fingerprint = "v1_sha256_77241804b5a26c361f24f88ed179c0cf377e93d388647a705478805bd6324777"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "511c9272baf722bddd855a16f1b5ec6fc3229c9dc4ab105abfffb79ecc1814ce"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 0A CC D6 0A D2 B2 ED 55 60 F4 67 DD F4 5C EA 0D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_30719a7d {
    meta:
        id = "3S8KTYho5GXe6I2VVq7D87"
        fingerprint = "v1_sha256_fce6cf265577c2ed6775b16a5afdd5d6ec6ec2be82d5cf786b49cb75c2c81625"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7822ff888410631fe2844b3c843319e9d135a32b75ecd497c3f91ec68c5b9825"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 79 D0 57 D5 AB 18 35 B2 0E 55 27 FC F1 01 92 CC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ec2b87b1 {
    meta:
        id = "4zPaGKdLqWYDTETTlZaqMd"
        fingerprint = "v1_sha256_959744b05dd6522dcf7e55796d32ad65ed137f7240c0c5137e570dc0d682763d"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eef13758a7f78dfda5386aee61d9ab02efd9057963fd4837cac1a866c8f17e1b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 35 2C 54 2B 8E 0C 2B 4F FE 99 94 E1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c9e89da2 {
    meta:
        id = "6boy7C8aMh337hOaOhy8q8"
        fingerprint = "v1_sha256_9a004468990ad2630d3a0d371d349c4357654f404657d7c46e6a6633d8231013"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "251f3eecf4f6b846ff595a251bb85fad09f28b654c08d3c76a89ed4cc94197d2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 01 FF 82 F4 00 3A 6F D1 5A B7 A3 EB CA 98 7F 60 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_326bc791 {
    meta:
        id = "7Nq12wApLydZC7i8Mu6fo1"
        fingerprint = "v1_sha256_85afe6aa6c209e33be41294466ceeb1fafdfc5e012acd4dc47802a25038ab3ed"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f8b4164773dfabb8058d869f4ae7a6d2741a885a75fbbcc51722c4ba4e145319"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 01 5A 5B AC 49 42 DB EB AB 59 8A B8 90 D9 2C F5 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_e822d2d7 {
    meta:
        id = "5dd9ywqntlGFoJlCFKZ5vY"
        fingerprint = "v1_sha256_6b3b35c4644e96d2d8621d5f64d6f20fbb1a05d4a5f793b1d98b1d2413935c1c"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1acfde9d39095bfb538c30f0523918bd1f2cae83f62009ec0a3a03d54e26d8ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 2A 07 4C F0 80 DF CB 55 86 83 23 83 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_cf230984 {
    meta:
        id = "3CGxkqD8JdWjtYpYc8aTF8"
        fingerprint = "v1_sha256_7d42b8b88d392336138774ae3beee7b0c0864a364ac16b950787093ab292b7de"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "746b1ceebc0116b2c1e6c54bd6824b58d289a6067a3d7a53c82d5527414d0aff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 0B 59 CB 3A 46 C1 6D 81 E8 00 26 DF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_082de32b {
    meta:
        id = "4kV05XLQxLMuO50EBFGj6e"
        fingerprint = "v1_sha256_f7ad29bb2e63e4b5957f752d8e83fc64009af643e82cd380ff14126844d4a328"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6a75f271addce817d0350ac7ec7eacc15bfb8bf558284382b4f88bad87606faa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 52 74 D0 11 18 FF EB BD D7 E2 73 5A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a47f5902 {
    meta:
        id = "2h58R5DfpOkoftIhkMFtGQ"
        fingerprint = "v1_sha256_6cbcb6f9c7a4f3eb0ce8389891178f7c0e38001f2b870cba33870948df8027ec"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "313d6d6e9ba8e2335689b4993b14e90beba6ed0cf859f842a5d625036703e015"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 37 E2 F1 6D 1C 64 39 E4 52 9D 9E E4 80 93 FA 38 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a318116e {
    meta:
        id = "WiVDdUgzMwR8fAe0eP6Rx"
        fingerprint = "v1_sha256_1a771cc98cb9496d80d9227aa20c6347e764d11b55c2f5bee6d508d864113fc5"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "53d60c9bff836ba832c39fecb2d57fffe594dfd0e9149b40f5c9e473bccbf34f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 70 86 6B 58 66 85 F4 F3 9A 5B 47 17 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d743cb47 {
    meta:
        id = "698b4Rib3QncKJufrRo8J6"
        fingerprint = "v1_sha256_25133d802732d67207006001a1cc66f9373755c59333d20e2be230bcaa66e0eb"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "70668430bda8e76026d01964200fdb93ae276e9af15d202613aec97107573c6d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 3C 56 D6 27 7A 99 7F D1 D7 80 87 32 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_21c05181 {
    meta:
        id = "5DKiNQasp68vyHta5SNJr3"
        fingerprint = "v1_sha256_1525c1a0d97e7327a0ffcb8ced2427955c3b163e21a499772bcc5ceb8bd3b98c"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "598d2e71d2aa01e03aeb2ad1ef037ad5489f3bce1e1bde0a3e05d73565f5955b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 20 52 32 B8 64 FC 3D 16 1B 07 33 A9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_276c83b7 {
    meta:
        id = "Y9mwGF5B5GLKFOC9SxCBA"
        fingerprint = "v1_sha256_a8b22b73a214acd531c8611716c173b79fcd6d583beeede4c6a6189c4f641c4c"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8071c7b74e7ca2769f3746ec8cc007caee65474bb77808b7a84c84f877452605"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 FE F3 86 AC 9C 1D 86 36 CB 37 0C 8C 24 7F 44 FA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2a46688e {
    meta:
        id = "4b45JFZZ3ZHnzopLYzAvHe"
        fingerprint = "v1_sha256_ffd3513831cce99f07e80b47f7df982cd9147be95afc65c927ecb6f3694318db"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d2ed769550844ef52eb6d7b0c8617451076504f823e410ab26ec146dc379935c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 21 52 17 A2 A5 CD 73 2C CE FE 5F 88 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_eb360bb1 {
    meta:
        id = "3Yb6MKyy1PkTBZ0n12jCjb"
        fingerprint = "v1_sha256_614f10b7a6d57b1a5c6c28182070a374e0e7c4ab11dd075c8d7a1cee040073e1"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "09003df4deacc194a94c0def0f5aa8a3a8d612ea68d5e6b4b4c5162f208886e0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 4C 03 54 CE 17 E2 C3 64 2C 3D 06 4C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_5f0656b2 {
    meta:
        id = "1VeiJSvowbVsO8TPMUVlRp"
        fingerprint = "v1_sha256_275788e920c9ea1cca4317062989ebfd93e90b481589c1ae8904a7c8936a222b"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c35a34aade5c7ac67339549287938171026921c391a3630794ac1393fb829e3a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 A2 25 3A EB 5B 0F F1 AE CB FD 41 2C 18 CC F0 7A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_59ff12f8 {
    meta:
        id = "2N5kPa6pr1FLTzOWzFuIro"
        fingerprint = "v1_sha256_39e9b047a3eb8a8be3ad7e162d9bbe79ea0d25f6c9e27bc56270c1b371f504e4"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f645d0f75ce7f1256c64cd7c52fbd2cc4cafb7ae1b30c39e73907fa01b8079da"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 74 67 20 93 D7 30 4A 14 8F 79 47 AD ED F8 99 86 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c3d5b526 {
    meta:
        id = "3BdsNDDf6J5UHoNkeVTzAh"
        fingerprint = "v1_sha256_9336fbf2af1545a1b53381a46d0748d691b3019ea190ada674e62e8a94db8b37"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "06497b526cebbfab81e7e0d55118007d80aa84099d99ee5858c822a616ad48a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 04 DE 74 F8 06 A1 C7 F9 A3 26 F5 83 72 F5 65 42 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_11e18261 {
    meta:
        id = "7ESzfqQgSS399Koe9BpWzv"
        fingerprint = "v1_sha256_34be8d3b73a1fba30214687c50a8794772642e3b118020a5aefb525a7ed08105"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "249b1bb49496b2db3b4e7e24de90c55deeba21fe328909a7d6fae1533d92ce9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 2D 4C 7F 95 4E 56 1C 98 42 F9 B7 D6 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_9262df80 {
    meta:
        id = "7PoJeyCk4wjRA54ENOlFkI"
        fingerprint = "v1_sha256_2292a1d6aa4afa23a01d71a851696fdcd90b49c5338723f66eb454a1ef8fe8a7"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "86e966dacad8d808ba568d9dc53eeffb4e8848fa8eb9516e97c13bed8317b814"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 51 09 AE 83 71 B0 50 7A 4D 72 42 5C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_72de26c5 {
    meta:
        id = "7Wwg8MvMbfcgCkEcZldWfL"
        fingerprint = "v1_sha256_9993ef8f0ed2f7f1795fb6633824b8322a51601d58774a22d89a61589be8aed7"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e74c5cb1bbea30e7abfd292ab134936bb8cd335c52f4fce4bb3994bd6e5024f4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 9D F8 93 43 AD D6 99 DD C9 8F CD 37 67 DA 5F 84 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_7f40a1ba {
    meta:
        id = "u8qYgiRkPUhv73WXg6D93"
        fingerprint = "v1_sha256_87a115960c279970439b7bf40f30d8b8b0ef1c7383dca6291ab2d43cb98f95e8"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "88eb72267896a9db69457a9400979772413f3208a41e6cf059c442de719bf98f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 DC C8 1E F1 94 27 B6 B6 2B 71 7E 6E 92 EC 28 13 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a775b53a {
    meta:
        id = "666AZZWUtVEH8NuUYLJtw9"
        fingerprint = "v1_sha256_6feddc4ca9df870e34f0f92bac89c779dfbb468f1d6b6fa9b4909684222a5b45"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d38fce27eafc1a8eb4c83cd043fe2494e5c9a4939ff3a2784ca43beb8839bb3a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 28 E8 92 43 4E 59 E2 52 41 3D 3E 0E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_5bcffcb2 {
    meta:
        id = "6yAwzdd4Tj3nLYM2w292mV"
        fingerprint = "v1_sha256_c8eb09a57469aeae7064f4b024c84cd08f13d88a6b9c0921fbb081ec9602e5e4"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5d1aed7bb03d8ea5ba695916d57d64dfdf4b02a763360eb9ccbf407dea21946a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 6E 88 9B B3 B7 F7 19 4B 67 4C 6A 03 35 A6 08 E0 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_37d465f6 {
    meta:
        id = "55L3VNoCbcKkU9Vps5QAxA"
        fingerprint = "v1_sha256_1e6db93b1f65d76f994315e5deccf1bc67bfae78adc4d19b9b8eeca4fed75808"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "381e6c630aaf5ca69f01713be8ac29b11869c8e6af28359e6933407854f086ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 22 A9 7A E3 EB EA 8C 98 81 6E 1E 5E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_58979ccd {
    meta:
        id = "3g3YJImk8XKrY1EUmtfjel"
        fingerprint = "v1_sha256_a15984c21d0748776695c6981ea9ade9aa6b68d74df3d0c5dff409624214bac4"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "12bf973b503296da400fd6f9e3a4c688f14d56ce82ffcfa9edddd7e4b6b93ba9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 21 40 69 1D DE 2D 71 48 85 84 15 D5 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_8d94d2bb {
    meta:
        id = "5WJ2snYrFBxIXJLDV9PlWx"
        fingerprint = "v1_sha256_25dfd4012307f0aab356f89519252ff6ebe3bb3ad7ac4b01d022cbbdd2b6692b"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7250c63c0035065eeae6757854fa2ac3357bab9672c93b77672abf7b6f45920a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 49 7E 77 B2 0D 07 E6 37 B1 3B BA 63 54 BB 86 CF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2b11268a {
    meta:
        id = "1aBGOl6TYKyDMsea9XwDRC"
        fingerprint = "v1_sha256_1dfe146afdf99630ea9d674c8f9144e80a6b91e6a5ca457bb83a7111cbd01c1a"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4a13f40561173347308fa4da0767af4244e899077b6e609805d61742fdea5363"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 0F 1D 3B 26 EA 4F FB F7 73 10 2C 4E D8 A9 8D 70 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b19d9b4b {
    meta:
        id = "1JEzgPJjXBGasZICPKgzR9"
        fingerprint = "v1_sha256_9ad288c0e2fcef4cc0bbcbe073d806af7f70b2a2e34909faa69c37ba705f2005"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "217f09c89a67f223d9b370507eb5433542416a6c1f1a50f2047fb9355dceb55f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 01 25 76 8E 32 D5 78 53 C5 79 F0 E2 16 3E C3 90 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_548079e8 {
    meta:
        id = "72I9h3JX2HcRtbY3e2YqbB"
        fingerprint = "v1_sha256_eeb67de15eb95a0b5adb12de02aa99e422e05ee0c77ab9fb8842ac81fe9b03a8"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "83679dfd6331a0a0d829c0f3aed5112b69a7024ff1ceebf7179ba5c2b4d21fc5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 30 13 85 AA 36 FA E6 35 E7 4B B8 8E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c3391d33 {
    meta:
        id = "5hdKaalaxoREl6veasCWGh"
        fingerprint = "v1_sha256_85383a86600e8d37c1e244f3a7cadeef958fdc0c1164ddf2d82c3cd3dcb65a1c"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d0a18627b9cef78997764ee22ece46e76c6f8be01d309d00dff6ca8b56252648"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 8D AD E4 39 C4 A8 9B 11 48 12 34 B0 B5 0F F6 6F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1abaf391 {
    meta:
        id = "5tO4IdlB6Q9GQRaHiMXbUZ"
        fingerprint = "v1_sha256_e4be0f697e2f2398e0222edb43a152ab8a2d1e07fad62b6b37e1594e56f8410a"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "37c903910f91654c1a68751cd3b4dd6adc1fdd3477bfb576081b2672be39f3e9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 6A 0D 76 08 17 D8 72 18 99 B4 FB CE F1 56 9D F1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_32ae7aa7 {
    meta:
        id = "60c4Wwiy9dfszPo7ursCQ7"
        fingerprint = "v1_sha256_cf231baf944f525ba58aa5d47f48818a257c8a692ef38798bda41389617a98fd"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c608a717ff6d907eef8c83512644561d3e18863d42a0f80c778d254d2dcd58aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 F5 BE 3D 05 57 49 9E 00 6E 00 EF 05 5E 79 19 3E }
    condition:
        all of them
}

rule Windows_Generic_MalCert_f11721e1 {
    meta:
        id = "50AF4R7nx6Blf6vSLWnpos"
        fingerprint = "v1_sha256_5398bb417e15f18d74751651db7dceb51c6e874a6665fe7977b37b2f226680b8"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "42b0c02bc403c0109d79938f70e33deea25109036c2108e248374917fa22f4a9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 01 F5 2E 57 80 3C C7 22 5D 45 43 70 34 2B 2B C7 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_6753855f {
    meta:
        id = "4AGk71VzHXrfnlkTVuyi23"
        fingerprint = "v1_sha256_17d22c0dde90d911888e36ad030d4ab404b393be0cfe37b6628cafce7795715d"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "bdad526c2010c6dfeb413ecd4972d5681104c1cf667fef1b1e4778ca7d96ec35"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 74 26 D2 1D 23 94 D2 EB 72 25 A7 FF C7 EE 36 BE }
    condition:
        all of them
}

rule Windows_Generic_MalCert_0c9007f3 {
    meta:
        id = "51tMdjYKEctvcnnCzHl1Vr"
        fingerprint = "v1_sha256_cf46d7f8b54fc7b7dd066670c62af217556f3074cc1cf3d312fc87999b027357"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e4fcfb24360d755e8d4ba198780eed06c0ae94bec415e034d121ac7980d1f6a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 01 C7 B2 3C FC 00 7A 6C A9 4A BD 7D B7 5E BC 5D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_10d5a0d2 {
    meta:
        id = "3mpjazbcA7MbWvzavtmXlc"
        fingerprint = "v1_sha256_449490da03660988920326ebdffcc79ef7bddb501af733a36d7d031b62a3f06c"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c974933dd65a10d51f07f1c1bbd034e1357193fa70cf51d3cbe03f8752aa0594"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 0A 7F 68 D7 A3 C7 8A 2A 05 25 EF 97 37 EA B8 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_6606e2be {
    meta:
        id = "4b5XCCXBCBKgxjvpvWGDDv"
        fingerprint = "v1_sha256_9a548e2c4c4416a8debefc8576081b8014864535101f7fab23e69c16314e3ac4"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c1fa31b49157e684fb05494dcf0db72d0133c1d433cb64dc8f6914343f1e6d98"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 83 23 A1 C8 0A 83 EA 88 6F C3 58 08 97 90 39 F7 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_0dece90a {
    meta:
        id = "AIeu6dJ66jw8k9lNstATE"
        fingerprint = "v1_sha256_f509b805633290b55a047fc93d775a07147286c70ea52b193767be710b9a7293"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2bc61416837f467bb8560d3a39b14d755f1c9f003254e74cc635e8ff6a00626a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 38 7C 94 76 E2 83 20 26 45 94 84 63 17 D4 65 40 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_18a6f221 {
    meta:
        id = "4IikEnv0IlNl8zVBSaYGOR"
        fingerprint = "v1_sha256_8fb12c95cd9deae15fc636a8abf825edfd7bdf6f8abfec54e25a641c3d024b1d"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c2614d4f0aeadbdf1cc6efbe9116f7e80393eb560e7cc96f5f0c2300f002d806"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 5D 02 53 3E 72 14 B0 42 D0 2D C0 FB D0 B7 C0 74 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_81098b3c {
    meta:
        id = "2IK54Gklk043YfTXF7Fm59"
        fingerprint = "v1_sha256_f950b5abca5df92763fe9b48be69fa8a2ffd0ad30038648047eb2a3c281e0e29"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "dc2358df8e7562b826da179aad111f0fdd461a56470f1bb3c72b25c53c164751"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 11 7E 18 46 AC 13 0D C4 FA 8F 3E 17 9B 5F A3 C9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_108e8774 {
    meta:
        id = "5q3p18WlazVitLqb2quZtl"
        fingerprint = "v1_sha256_4642e728e2e30ee80fa4b741ab62ec32b3a826db26b9237d9adedb555c8e4d78"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ab21d23f3f642b1d4559df845052d50adce1e0bcc9a0fb88042e72f2791c3a30"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 0D E6 76 A4 C5 AF 15 BF B3 77 1C 14 2A CD A8 FD }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a8d852d0 {
    meta:
        id = "1QKz8zw7XNczDCX4avzwtD"
        fingerprint = "v1_sha256_b02e3ba3d75a17e1cc0fb2692140c5dd89fd0c1ca812ea82ba16300218fab351"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ce7dfe11133790e7d123fd7ae1bf7412868f045cbe4a0631a2c7b5ba7225113b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 30 EE 7D 2A 15 85 FA CB E9 3A 8F 0E F8 60 F4 6F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_70d7fab0 {
    meta:
        id = "2HljKylZlumXVO6qGiGsJM"
        fingerprint = "v1_sha256_dcb3db2d3a143acf5495ee63ed73aec0b77e889d8249ca0f14c2327f0f2adff2"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c3ef67ddf94f795f7ba18e0e6afc504edbd8ed382699bec299cb1efed9a1788a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 34 9C 35 32 E8 6E 9E 1B 77 CB CF 7F 12 D0 5C AF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_17a7e895 {
    meta:
        id = "3eyZDfT5JTleHE7YI2rLFh"
        fingerprint = "v1_sha256_d7b254dff01ee1158e86e4b58fd555f85969cde2c90acae10f9e7d5938cc7f0a"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5058a3469d589bdf9279a128db92c792c9aaa6c041aa20f07c4c090ab2152efb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 6F EE 7E 57 96 71 E0 C3 36 CC 10 DD 54 1D C6 98 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c14990fa {
    meta:
        id = "40Aqxz3IufX3vozYnnUKBE"
        fingerprint = "v1_sha256_fde11ccb0e4a2175ceb7431c9bf75f615ac454fd33a91859bf1c74e69da630c3"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ce4498bb0e9d8ff33ec55a521c0ba64c7d5ea8c45927496109a42dfcaf4b9ce4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 08 3F 4C 45 67 8D 2C 9C 7E A1 06 C9 00 03 B6 13 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b2d03ddb {
    meta:
        id = "3AvqMlMTNpKDT6iCoCEjjG"
        fingerprint = "v1_sha256_20e74c1d0651acbb9bea8bbd0ce647bac0956470b2dc141c6b29df1ec226204a"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "58146fe5847983e1382fafddaa1417d1506da70bb6dfe940592726c04908f4c4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 04 BA 61 03 59 2C D6 22 38 10 E4 88 87 08 DE B5 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_35a7e8aa {
    meta:
        id = "5gIonrWAf92xD5Q3JRfjC4"
        fingerprint = "v1_sha256_fa35f56f36521fca6a9de9e18a0bad3256f8eef89ec8e6c0e53847f4fee8039d"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "cfb5cb22b2b882d620507a88942a4bfe66fd65082b918b1b9a6699fd56ac5a9d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 50 5F 39 51 5D A5 58 18 23 24 C2 CA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_09dd7d76 {
    meta:
        id = "57LBhzAeKHuCPFdTg0Yd0e"
        fingerprint = "v1_sha256_7992dfb6b055aa4921f3b07883a8b05f0736cd8f98843f65a4b5157da670662a"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "501f636706a737a1186d37a8656b488957a4371b2dd7fcc77f13d5530278719e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 02 D3 48 95 65 F0 54 1F 0A EC 61 84 A4 98 1D 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ad55864e {
    meta:
        id = "4Oro7zJwfbbs5JQtaPpywh"
        fingerprint = "v1_sha256_a415f0c2a5420ad0698caf8295bc26c86b3b8d9e9f005cedc3e9312c4cf1fc31"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "654636d8d996e7aa93e93581f595bf63d32a3fd18c6b84d5c3b31de113fc1740"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 23 10 78 28 3B AC 1A 1A 90 F6 42 02 E8 41 77 AD }
    condition:
        all of them
}

rule Windows_Generic_MalCert_599b3a08 {
    meta:
        id = "7Tvp4Q0NyLLghk3zjX2s9s"
        fingerprint = "v1_sha256_ec578ba54d756c1c6e9eae335fee38ec1cded7ad338b9d76d479530ab21bd858"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5a1b32b077d39a9bfae88dca7a9e75be5a1e6ace2d3ecb8fc259fdae67d848a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 2D B9 F8 38 04 C0 78 54 A7 5A B0 8A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_724bed8d {
    meta:
        id = "6MhgL2voyxS39RwZbTzWTg"
        fingerprint = "v1_sha256_bc3e3678e20087c748a8fdccbe32ac546ba1748b9730096de852951985e7c0c3"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "850c3e89c9d98b978e03a837eb24e48ed85b495ca486660016f51f3f41712611"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 0E EB 82 9E EB 4B 17 CB 6C ED 4F 42 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_95327249 {
    meta:
        id = "3REDnwSzrfkN8nnwOyX0VI"
        fingerprint = "v1_sha256_592e5aa25fc7a8f2381f358ffd0229fcc0608d3e35810ecc5d26137c7e05cbb9"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e99a5e18f6772adaef7d0f8fb13de41eb2c25f25e292c2ea278a0b473642c7eb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 72 BC D4 DE 0F 46 24 38 EF 7A 30 6B 0F 98 E6 68 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_fe1dfef0 {
    meta:
        id = "3md3yLeJ4GLv7ghYDyQUpW"
        fingerprint = "v1_sha256_23bc3bd5923d941cfc338174fab1e8e762873d59ee88125f43d096a622480ba4"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "0c9d7c08f2a74189672a32b4988f19cab6280c82a4c4949fb00370dae8c4b427"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 3E A9 D7 D2 B4 B7 4F 29 56 9F 50 6A 64 D5 CC 2A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_726cc1c1 {
    meta:
        id = "oIxMQafGk3CqcPrMnU6l1"
        fingerprint = "v1_sha256_fb75f788ff855ed2c4ecce9bb271e37e902903c9a3972f9080d6619d4f639489"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "77e103eaffea71d35b1d06d64fdbe546261e95d6360b608e1688c4c437f4da5e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 6E 13 E3 2B CD 62 7A 1D 6C 39 EA 1F 17 46 76 3C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_7749cda8 {
    meta:
        id = "7DRkFUwr5tUAJTGv32ZqQX"
        fingerprint = "v1_sha256_f020f03c21a0d2a0b34980dae7f4d68c1b355347b14a315381c6300c48ed67bc"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e0f9e51835788efa869e932aab139241e0363f6b44fe1c6c230cc26b83701b65"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 6D 30 BD 4D AC 27 22 DE D1 22 24 7C 01 28 6F B1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_344b6b05 {
    meta:
        id = "76Rdt8BJKEALZe25EyGvKk"
        fingerprint = "v1_sha256_b41a2cb29169c93d9837685359bfa6dcddd9c0394b784e870be18c5e6c4bbbfc"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4d91a7e24ae7fc3d6e5423c0008707e4e94b0bd3cef153639ba4ec90d61f3c98"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 02 0E B5 27 BA C0 10 99 59 3E 2E A9 02 E3 97 CB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_8228dd5b {
    meta:
        id = "2wYrx8BJmN9uJBZsP4kDqG"
        fingerprint = "v1_sha256_dc5ae8ca9c107f046539fb6cd9e494af13378b6dd54b95fccf8d0cc3222760f5"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "82a6cd7d7e01b7bd2a1c2fc990c9d81a0e09fcef26a28039d2f222e9891bfeff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 37 E3 20 53 B0 0D 56 23 68 28 E3 D9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d1751a98 {
    meta:
        id = "4Yzzqa8jJrzRlDPsOnY00w"
        fingerprint = "v1_sha256_62f0235af986decd02bad757e207a29e48fdba549f94837680d018c68a5a625e"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "9959fc6e686d668f8e5e2f3935b6e8c86b547150acaaf8d9687de4fa4d1c937c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 7D 2C 9D 9D EE F3 AA C2 1C 89 59 76 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_578f96d1 {
    meta:
        id = "4SgMhwaLQHonPRSiNDO4W3"
        fingerprint = "v1_sha256_2dd4c55e86d7955e44249aacf1a235e9dc7ca97e6aa11778a92546399d27d5eb"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eeb8cb6bc1340b2fa84a2d79ae68c001e05caae3be5c446220dcef5da9579d06"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 C0 E2 8F 6B F3 D8 D0 CC 00 30 6D F9 02 D6 EC 0F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_04e5ae93 {
    meta:
        id = "6accRr0qQJpCLp84ywlATH"
        fingerprint = "v1_sha256_0c52771b41b23b0f0e48636266c47e5e695a5cd9051a25b150d565840414961f"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1a983e597abdb37653baba58de85bb8e55c6f20aa6bcbd7420b9d14dca586bb7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 0A 43 AC E6 5F 1C EC 7B 0B 10 8D 80 E6 AB A4 BB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a196f680 {
    meta:
        id = "2WhAchQgpwxLfgImwXuZzn"
        fingerprint = "v1_sha256_f8deb6e931ffa133e5ad85c332143963ebfc7b5032f92e46b83721b6156e7974"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "45fdcd215d2dec931b4136c3b6f4807d53db7a0e1466bbb1afc9d68e872053d3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 2E DD 68 6F FF 3B 20 4C C4 23 16 73 FA CE AC 92 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_21673599 {
    meta:
        id = "52fnVlV4RZh0cXuRP6VLrN"
        fingerprint = "v1_sha256_b1b3780c9b1d5dabca7d5b2ae02f5f8fc81cc49cdcc3eab2e2544afb5386a5a7"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "804641f152a3e6994e05e316224a5c8f790a2de5681dd78fa85674152e74677a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 1B 3C 13 05 D4 95 D4 9D 68 C7 C0 18 58 3F 25 31 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_321cda6e {
    meta:
        id = "2GiwXbGiPk9p4T9K48f9sC"
        fingerprint = "v1_sha256_939c3a5640c042a820f7abb090099280e916bfa310b0f9c53e7286888828c267"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "567115a08d2eebcbdea89d83dd9a297020c360b3f99117b990eb3fe95501acc2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 B7 D1 97 55 1A 90 91 8E C0 B3 20 F6 DA 64 B3 0D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1c42f7ff {
    meta:
        id = "3RHw6fC12mNl9iMZK30BVs"
        fingerprint = "v1_sha256_910a8be35ee4e753e518c528d3489732074c7ed69407afebfdb229e812d7208e"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1618bb5c1d7874a4083ab40eed1106ec24679a64e564752594964a998eb93dfd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 3C C9 EF 0D FC 14 DB 49 96 6F 02 99 8B 69 32 FB }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ae04906b {
    meta:
        id = "2rpkLaa7A1ZTPM2cZS3jbf"
        fingerprint = "v1_sha256_0844d8658270172a3fbc2e9e39fa46e52535c517a7f8a20eefc74a5761065631"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e115cd3f7f9fb0d34d8ddb909da419a93ff441fd0c6a787afe9c130b03f6ff5e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 02 68 2C EB 56 82 17 E7 B0 DE 48 94 25 B0 D3 C2 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_cd89378b {
    meta:
        id = "6ZIaOA0mWdkOoDAWUG9PAb"
        fingerprint = "v1_sha256_3158c9ad37ef80e7fde65cd240898f3097532cb87699cc172ad0ea89ac8cfbff"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "763a4ca9f7ae1b026e87fe1336530edc308c5e23c4b3ef21741adc553eb4b106"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 65 98 E9 51 40 7E 30 11 49 D5 60 EA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_401d2001 {
    meta:
        id = "xfbnisiBfBFatU8ohCB9O"
        fingerprint = "v1_sha256_60abb19457dbc795af13cb0a21ba2e44f853e16e8312d0b5a3ffe70c2bfb6ef8"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6dae04b373b1642e77163a392a14101c05f95f45445f33a171232fa8c921e3fc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 4A CE 35 43 66 56 43 D3 AF 3E AD E4 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b5f08eaf {
    meta:
        id = "5cycFJB0cxm8IK2XsFjVf9"
        fingerprint = "v1_sha256_649d5fcfc8a5da8f60630a088641269666eaf6b5a65da5b7fc9c6522dfb7a771"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "553e275198061d8c0d35ce89ac083909f12091ed761b8977700548bc968b137a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 63 1A 2A 12 F9 3A A1 2F 79 34 D0 7A 16 A6 54 16 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d8ebed26 {
    meta:
        id = "1TK59NVsFvPPkDo0KyAoa7"
        fingerprint = "v1_sha256_8f1ce1aa3f19648c26c2591f8ba4cb4d6416a1d92d0ae04cbb940a4c5c0bab17"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "51d03995f68aa54f065b4d23961de01392f9d584740932f6a32312ae2ff34304"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 79 E1 8F 9B 4E 7C AC 3F A1 1E B5 DF F6 A0 51 E0 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_50108ec0 {
    meta:
        id = "31b3gySkbQbTu28DbKbB4E"
        fingerprint = "v1_sha256_6473bd296796ac68e4461d9a610667a85b838705c577263c4ea3633f48465866"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "53091c881ecff5baae1e998a15178d8e9da8f0dcd896d036a82799de5fbe605f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 12 11 21 C4 46 16 E3 C6 35 CF 29 3F 8B E9 DC AB 68 5E 6B }
    condition:
        all of them
}

rule Windows_Generic_MalCert_24178164 {
    meta:
        id = "7Z6YWbd1DpMBC3Ww4XfR6e"
        fingerprint = "v1_sha256_fd97322e267b64d5d19fdb9deaefc651d610a70c4d00a1509aaef927616753ca"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2074099eb6b722d430cbd953ec452984acb84e04c23ddf7e5c9393f906fd910d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 34 DE F8 02 47 9C 8F D6 3C 6A B6 A9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ea0f93ba {
    meta:
        id = "6BlHyDph2xWIxw6Nwh8LM4"
        fingerprint = "v1_sha256_416d7eb3f61830320800edcd45427130bd9ff1dfc7c07508e40d3457a1e456b6"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8143a7df9e65ecc19d5f5e19cdb210675fa16a940382c053724420f2bae4c8bd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 4D B8 E2 54 19 B9 6C 60 FE E8 65 C7 01 B6 2D EF }
    condition:
        all of them
}

rule Windows_Generic_MalCert_08e6d68d {
    meta:
        id = "7c1jjCj5L19qdwVkdhXR3M"
        fingerprint = "v1_sha256_24b96b27b9a57c17f83e237123e1067693367e1d1e245f82bca4ecf99719afc8"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "19d900ffefd8639dee4d351404e06f47852771e8d2544515776cc1abec4dcecc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 40 CE 44 CE DB 44 70 A1 40 31 F6 E1 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_33d0a7b5 {
    meta:
        id = "18bK7MuY2pEyV7Ml8Qm2X9"
        fingerprint = "v1_sha256_fc4475cc624ad7e48d2c586dd8e9d37e989a3bcdacdbf3f8cca83302e189a5d0"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "67ebe950959d5c68b5d1423504d1aed80d38e0bfaf11943bb0a4b7303142e0ed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 77 FE CF 9E 4D D9 53 10 06 4F CB 0E 42 81 0C 06 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_65514fe0 {
    meta:
        id = "6mVb0Mom4ioVEkoyzQeD0X"
        fingerprint = "v1_sha256_2941c4ad26831fe0332ecd405e18f029faa1062f2b1660beacd3aa6c70d59502"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "0c5a1ab9360a9df7bc8d3fe9d8570e43aed3fd2d3ae91dab0ba045dd03e47e83"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 08 D4 BF 5A 52 9C 72 59 97 E0 F6 C5 26 49 5D 2F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_7bfcc952 {
    meta:
        id = "4eSVO4FqwEhB1lEOwV8tjE"
        fingerprint = "v1_sha256_fc6e146db90393ac625e370c4da02172503f38ce7f941b3be9683bc89362dc35"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4b264458f5383fdaab253b68eefaeee23de9702f12f1fbb0454d80b72692b5b5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 08 D2 A6 70 58 24 F5 5C 15 BF 66 C6 7D B5 23 A9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a632cd10 {
    meta:
        id = "38gHCwOICYQ3mzkuzyoYqx"
        fingerprint = "v1_sha256_029600b0d29f5e3301831d69056f0be78767f78701b8dd114326136322f50883"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "74b3248b91f953f2db5784807e5e5cd86b8a425ed9cc3c1abe9bee68fcb081b7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 11 44 D2 65 3D 4E 2A D1 9D B1 08 F8 66 19 49 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1f95f236 {
    meta:
        id = "3m2ywYAp8j0lLwpmef9l6c"
        fingerprint = "v1_sha256_acbcc55925e81f2da6b4999f85a995401065a39da20444ee0c2443508fc982cf"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "7e99bbab3a4b51999bfd80de8e8f5ecd4d1098757cb0f00202503fa7179c3a08"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 7F 89 B1 89 5D 7F 80 BD 14 C2 73 B8 7A 75 03 89 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_389a8f1e {
    meta:
        id = "eRvht5eCk2EIz50u9xY9H"
        fingerprint = "v1_sha256_ce32a622ec104259b70b06ebeecacd421308e056f0e1d17d58dedb94f305811b"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e87c99c87a42feba49f687bc7048ad3916297078d27a4aef3c037020158d216e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 0A B1 98 49 5D B9 8E 5E C6 1C D9 93 C6 A1 6F E7 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2a954560 {
    meta:
        id = "grK7oHVIRpf7F2MOdYArz"
        fingerprint = "v1_sha256_a6f35d394165706e358b904e8ecd0dfa77371fd47f314efedc821521b28ca9d6"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "fbd914b7d9019785d62c25ad164901752c5587c0847e32598e66fa25b6cf23cb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 77 E1 B3 58 54 DF A9 8B 97 02 C7 F4 C4 FE D6 0D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_f32fdfcb {
    meta:
        id = "5ysRc9ftr0BHdV8FpDGutQ"
        fingerprint = "v1_sha256_d9b37f3086475c7ccc30e532984689ca2fc0ad6bd334de3dbcc50999217e3ee8"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "9c322e9a3500cf1cc38eecdd7952422f592551b9cd5493045d729d50de181a12"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 3C 0C DC E0 B2 56 10 11 DB 47 BC 01 1C 6D 7D EA }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b8e60712 {
    meta:
        id = "3cN9W3NoQqRRi2Np0GW6Jk"
        fingerprint = "v1_sha256_258b5f8bf90c933e4ec5e2827dcfffd4792b20214d74faf762e2c3875c7d4b60"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "777325f2c769617cf01e9bfb305b5a47839a1c2c2d1ac067a018ba98781f80e0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 06 0F DF EF F7 3B 5C E4 69 E4 9A 78 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a925949c {
    meta:
        id = "c6udyllyLmkMP41MrRcK0"
        fingerprint = "v1_sha256_0eda3bb4ded0e057358106100704f1ce80a40587fc1090d4a9e63b070c58afb0"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c33ea2ccb5a6e4aef16cfb18f64c5e459ce09d7d7d5dc963697c496e61f54a91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 15 D2 21 01 46 49 44 AB 90 81 D4 0F }
    condition:
        all of them
}

rule Windows_Generic_MalCert_42e6a3ea {
    meta:
        id = "5wOamaUk2XayEIVT2awwHI"
        fingerprint = "v1_sha256_886687d382c59d1f309658b723228b8c3b20b7f7c49a4aaf67104ded948488c9"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ebdd5efd08c7f68a57850f4967f259a1cd4acb035e5ca6bdfb64e22b17f3c671"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 07 53 C9 D0 B1 D9 AC 84 FD 84 DD BE E2 4D F8 92 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_efc31315 {
    meta:
        id = "2QN8XcGj2fyLSSOCxSolLk"
        fingerprint = "v1_sha256_8137fd3849668dd93a06f6ee9f08816563cfa7746a95cfa64e57471e9cf3a268"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "83b969335b62f450b0b07f994d95cb40fb7c02557966386efceb3d89b47d32f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 50 3B 7A 1C F3 B3 F3 58 05 AA 8D 33 64 CD 07 A2 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_4cfcf573 {
    meta:
        id = "6sN0hwugIaBkzdgURPyyIg"
        fingerprint = "v1_sha256_277ea982e7259cf517902242f489df5358775e6787614078843de748fe21c80b"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "12c98ce7a4c92244ae122acc5d50745ee3d2de3e02d9b1b8a7e53a7b142f652f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 70 AA CF 51 0F 5C 8A 89 3C 51 04 B2 DB 31 56 33 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_5b803f85 {
    meta:
        id = "NsQ7GLMldLKfwityWFUlR"
        fingerprint = "v1_sha256_60ec90a4ac01057ccbe2b451eb1a3f48d8a391be03f8c37b14215a93f365e2f2"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6bddbba9adc1a71c245705ca131c99f4d2739d684b71b2e6e197a724838af964"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 45 F7 5E 71 E7 32 09 CA 1E C5 D5 D5 D3 F2 88 81 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_9a68ab4c {
    meta:
        id = "7btG8btHAWuW28bUGzyNLl"
        fingerprint = "v1_sha256_bde9dbe62af5aaa9a6704dbf06510227a205430a500ce4dfb84b8c78b608c10d"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8cf87dc9c594d145782807f51404290806a2cbfd7b27a9287bf570393a0cb2da"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 D4 EF 46 9E 41 0A D1 3E 8E 08 DB E2 E9 AC 0F 93 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ac249f11 {
    meta:
        id = "7hEGuhpSGaxl0fqUdeuafX"
        fingerprint = "v1_sha256_733593bce5aa190bc3fbcc901ea0dcf0f9f726b2eba829a6451f7f7af6276dde"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2449b3223695740b32c6c429ded948a49f20c569a8ebaae367936cc65a78a983"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 31 F7 D1 3B 36 05 F2 7A 3B 86 F2 BE }
    condition:
        all of them
}

rule Windows_Generic_MalCert_e659d934 {
    meta:
        id = "4m48KHxdpT0Oarz1ZY2sah"
        fingerprint = "v1_sha256_5897021a67f77a122360c209bba8f37fd2a9cc3bdf54fdae487b0ff7d7869fde"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "60ba61b8556e3535d9c66a5ea08bbd37fb07f7a03a35ce4663e9d8179186e1fc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 47 88 4E 54 A5 98 A9 0B FF 2B D3 18 38 01 02 67 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_1dac3f8f {
    meta:
        id = "5ZeusB7U9h9dy2yKPp79qw"
        fingerprint = "v1_sha256_11f4794440178b19e0583ab3c24ef1b2ca4227d88ae0290f2f6685ddd8312912"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5569d9ed0aaaf546f56f2ffc5b6e1ec8f7c2ec7be311477b64cc9062bb4b95a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 C1 1E 1A A0 5B D7 47 EA B4 3F B3 1E B6 A5 31 DC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_c31e42f7 {
    meta:
        id = "4fBiOzqDfg0vSxHpz0aOYx"
        fingerprint = "v1_sha256_d5acd745ec5c077aceb5caed0de9594d89454c6a636313f9f9bc6580d2c827b5"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "17f3f4424afc18df18b9a9b36408e3f214ae91441f71e800f62dec240563dc6f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 84 9E A0 94 5D D2 EA 2D C3 CC 24 86 57 8A 57 15 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_152fa250 {
    meta:
        id = "3S0XR8FK0oW3fuaTs86hjn"
        fingerprint = "v1_sha256_1dd6b142cc14df84595190dea14e5bf20df8e3c72aff4a8ec24fc3047960342f"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5ded120267643bc09f3c66a9d64165c215d8f74b1b9b398b7864d1f61fbcfbdf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 14 C0 AF 4E AB D0 5E 63 C3 D4 B3 38 E0 BF B7 E3 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_728e5383 {
    meta:
        id = "5pkE61vIVsc8wHzD5L6kR7"
        fingerprint = "v1_sha256_b64eae1f960390d642ea7ca7934e5d99d5fe39e9f28686309201140745373a42"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "a4a1956522fefb1fd56af705b139320f39b0a5964d8d66c2c0bc6676dacd3983"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 DD 67 00 A6 3F D6 D3 A2 CF F5 F8 AC 95 54 FC 4A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_3db9ec08 {
    meta:
        id = "4MRkv6aHgeta4TBiMIysp3"
        fingerprint = "v1_sha256_d1fd51887412ffbeed0e9c5752f22117224bddb42fc2ddb90c81a238ab3cab21"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "3a231e482fbc0d301aed8f11378d255839ab9f858a97e9bdb07e40a775a78851"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 25 EC FA 37 8F 74 0C 6C E8 4D E1 81 D0 F5 43 35 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_45f72bf1 {
    meta:
        id = "u60kmsmTWJiUKiVgqrXXe"
        fingerprint = "v1_sha256_fa1c992deedd1daafd1d6769daf76dc5854b230daca4d31da3c6e69b7ebd07d1"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "79b6e63218982c1e85a5e1798c5484e7e034cfecbe9f2da604f668fda8428af4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 69 C5 54 75 FF D7 B1 A2 47 42 96 E1 4C 5C F8 D9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_2863b2d8 {
    meta:
        id = "19PGlLswvu1jygJLR6EN2F"
        fingerprint = "v1_sha256_939e8054a3f0425b05c6794d8186610241d6d46f79c0fd02ffe7ab2dd6e4c6a2"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "37223c02e25178395c05d47606b0d8c884a2b1151b59f701cc0d269d4408e1e5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 56 4C 3F 65 1F E5 1A 68 50 4F C9 7C }
    condition:
        all of them
}

rule Windows_Generic_MalCert_397a556e {
    meta:
        id = "Vrw3qeERDCGugZNq8ANu2"
        fingerprint = "v1_sha256_e007b35cb2e8df6ca7154b4f6ee0185c88b795cee58e2734c9bfc605c199e4b2"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f13869390dda83d40960d4f8a6b438c5c4cd31b4d25def7726c2809ddc573dc7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 1C E3 9E A1 C9 FC 35 F6 CC 05 A8 40 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_577c572d {
    meta:
        id = "1zxXxE2ErYT3QeilYvBsDQ"
        fingerprint = "v1_sha256_4621e4ffafaa314b1356670860751d34e70274aba13cbe7822879d0a0b0cb6d0"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "a941413f86e84dfe14f1ef161ff0677971359fd5992f5463965e5754aca6115c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 4F AF 34 C6 62 37 73 26 A5 85 FD 91 02 8C 65 76 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_a3c9c9be {
    meta:
        id = "5yQwbDUN18Ih2LLmpTbjCv"
        fingerprint = "v1_sha256_fb2b31c2d55e5020327753656c736fb8c20d73d9f33b00fae20ca530e69e2296"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d860e6c483cae03f42fc3224db796a33289f48f85dcc8cd58bdc260f9e68f2ad"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 2F 14 7E DC 60 E9 34 24 AF 60 A7 AC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b650c953 {
    meta:
        id = "2swc6nXI3xsI9yQVZjKgmc"
        fingerprint = "v1_sha256_90fc5703360016dd91fc0214bbf5afb5ed44ba03b176bffde6570718fc41f4e7"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "ceb75880148e05af7e9d029ee11d33535346ff5161b2bc506dbadd710688b9f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 20 E6 5F 5D 29 B5 82 24 10 50 4B 1A C1 83 CA 3D }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d15ca49f {
    meta:
        id = "5YgyhS4cvc0spRIDOmNtm1"
        fingerprint = "v1_sha256_0c52d5a25e7ed3e421c71c64606dab1e3add17965444d5db1bb8290e5092afb4"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e912bb10a2371ab0f884cd38bf2940e056f6d2e4aea4010303e98a7a5edcfcbf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 71 AC D1 EC EB 75 F9 2B DC CB DB 9E F3 6F DD EC }
    condition:
        all of them
}

rule Windows_Generic_MalCert_e507f27b {
    meta:
        id = "1TPQqcQM5LWYo2XKKsq6Kt"
        fingerprint = "v1_sha256_c91ecb953feb379cb8cdbc6ac595f5f44364bc1eacd2328eb201291b6a5944ee"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8b5af508dcee04dbb7dabdffeff03726ef821182ffdb8a930af57e9e71740440"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 7A 06 2E 41 04 BF 96 33 E5 CD AC 31 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_ed5b8080 {
    meta:
        id = "46dVgWiG62NIt8iJA5Rou6"
        fingerprint = "v1_sha256_a093e9ad4eebbc1304d409672b15cd7e84299315678514e44e5d85d231ff1110"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "db827af8d120c894e82590ad6b4ca1d19e8f41541a7d3ea38734443d88deb6fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 4B 6F 02 3B 59 59 7E 8E 95 3D B4 CD 7C 0B 52 5A }
    condition:
        all of them
}

rule Windows_Generic_MalCert_b8c63d0f {
    meta:
        id = "7Td3T5CuDXLJGJKrNWqzkr"
        fingerprint = "v1_sha256_5e752226c27349637c0309c928afe86a82827078c8198e91d1433b14c3591acc"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2f35445ba043097f38efbd160c6bdd6ba0f578165c295e6d31bfd179c3b6c4a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 23 A5 73 F8 85 C7 1A 52 D7 A6 E3 21 75 96 CD F9 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_afe226f4 {
    meta:
        id = "2iSnIvIBAQTmtQGltyZu9G"
        fingerprint = "v1_sha256_cb02b04069419526e80094a94e48749400ab3ebec7483ab4cfba96ed285af39c"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "3b66d49496a185b70e9f4a4681eca1e0f8a0d00fdff4f4f735b8c4232f65fb95"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 0C 21 39 10 E0 20 B1 96 D0 A9 D3 53 B4 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d9a0af1c {
    meta:
        id = "3tCpqQjFNIsjghsvlnYoHN"
        fingerprint = "v1_sha256_795e34d0b842b4b438c77a6835831d49990771906e38fb24eb0435aa328b4504"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1ed9d2d773a2f9ac13fbf53d806dee30d43ab5b736513fafb5eb5abf23940462"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 10 66 77 7C E3 BF 34 92 24 23 90 B8 6D BF 64 8E E6 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_4b7c2e6d {
    meta:
        id = "1PpdDYPZvuCqMzfqLO4nlC"
        fingerprint = "v1_sha256_042975711a9a2acd7a7cae682815cc892ce6ea606ee58a6b82e6aea3d3486855"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "df0553b9d93edbbc386466b1992dce170ba8e8d5e1cad6b7598a3609d5f51b5f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 E4 0B 23 79 43 2D 73 AC B1 96 B9 D0 9A BC C5 87 }
    condition:
        all of them
}

rule Windows_Generic_MalCert_d3a0db6b {
    meta:
        id = "6Ddq21qHgRgZNGyTwQetX4"
        fingerprint = "v1_sha256_36b197c3f3431d1bce00bfc1a04ce4350d6fb1b363325d6092c096ae50c0962c"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d0ce783b1582863fa56696b8bc7c393723f9ff53552fadc221e516f39b3c165e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 08 32 EF 74 6F 16 E6 73 1B }
    condition:
        all of them
}

rule Windows_Generic_MalCert_148ea98b {
    meta:
        id = "2TSO4l9WknAqUaZgxoKfZx"
        fingerprint = "v1_sha256_a74e73270b49d62819e5ee6a9dc89f3d904387b53eb4bb91793a824d4cc445b2"
        version = "1.0"
        date = "2025-02-05"
        modified = "2025-02-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eb8ddf6ffbb1ad3e234418b0f5fb0e6191a8c8a72f8ee460ae5f64ffa5484f3b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 01 02 02 11 00 D5 E3 54 50 B8 47 E0 61 38 C2 B4 74 49 25 D9 67 }
    condition:
        all of them
}

