rule Linux_Hacktool_Flooder_825b6808 {
    meta:
        id = "1jG5KnGnLmBfvPL7yyQbL8"
        fingerprint = "v1_sha256_f5f997d8401f1505e81072dcb0e24ad7a78f0b56133698b70d8dd93ef25ddaf3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "7db9a0760dd16e23cb299559a0e31a431b836a105d5309a9880fa4b821937659"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 83 EC 04 8B 45 E4 FF 70 0C 8D 45 E8 83 C0 04 50 8B 45 E4 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a44ab8cd {
    meta:
        id = "3Bu4oNfICfWZNoWtf3txA5"
        fingerprint = "v1_sha256_a0501f76aff532366292189d34a57844ba999748b94f349be2f391dfd96e2106"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "4b2068a4a666b0279358b8eb4f480d2df4c518a8b4518d0d77c6687c3bff0a32"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E0 03 48 89 45 A8 8B 45 BC 48 63 D0 48 83 EA 01 48 89 55 A0 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_7026f674 {
    meta:
        id = "1p1Yy6r04RiiDitEmfuw6X"
        fingerprint = "v1_sha256_ec8ece1f922260f620fb30d82469f77a4d0239da536fc464fc37a3943cd6e463"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "b7a77ebb66664c54d01a57abed5bb034ef2933a9590b595bba0566938b099438"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 08 1E 77 DA 00 43 6F 75 6C 64 20 6E 6F 74 20 6F 70 65 6E 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_761ad88e {
    meta:
        id = "301UWqLwwb1gHEigK4R5rS"
        fingerprint = "v1_sha256_2b0c64da713e2f8ff671cbe086638810bc02a983d42851e78c68a57bde9f023c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 2E 31 36 38 2E 33 2E 31 30 30 00 43 6F 75 6C 64 20 6E 6F 74 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_b93655d3 {
    meta:
        id = "6WvINDHzunFhiO3OAHOWCp"
        fingerprint = "v1_sha256_34cb06385543c6c2c562f757df2f641d8402e7c9f95fa924e17652a1c38d695f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 49 89 C5 74 45 45 85 F6 7E 28 48 89 C3 41 8D 46 FF 4D 8D 64 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_af9f75e6 {
    meta:
        id = "54RzPwCPgdElibUl42XSGf"
        fingerprint = "v1_sha256_b74f5fad3c7219038e51eb4fa12fb9d55d7f65a9f4bab0adff8609fabb0afdab"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 C0 C7 45 B4 14 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1bf0e994 {
    meta:
        id = "3WnOK7kwakz6MPEGgNn9TU"
        fingerprint = "v1_sha256_2c1099b8078ac306f7cb67be5b5b5e34f57414b9aa26bdd6c26d3636c80846cd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1ea2dc13eec0d7a8ec20307f5afac8e9344d827a6037bb96a54ad7b12f65b59c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 05 88 10 48 8B 45 B8 0F B6 10 83 E2 0F 83 CA 40 88 10 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_d710a5da {
    meta:
        id = "3P22KmsS9yIK2Fp6rOaliN"
        fingerprint = "v1_sha256_118a29cc0ccd191181dabc134de282ba134e041113faaa4d95e0aa201646438b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 24 48 8B 45 E0 48 83 C0 10 48 8B 08 48 8B 45 E0 48 83 C0 08 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_f434a3fb {
    meta:
        id = "5zhx9v3UzacweYzKytbVEn"
        fingerprint = "v1_sha256_11b173f73b87f50775be50c6b4528bd9b148ea4266297aec76ae126cab0facb0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 48 01 45 F8 48 83 45 E8 02 83 6D E4 01 83 7D E4 00 7F E3 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a2795a4c {
    meta:
        id = "2TaRIQN63mIQ0eHIbm2SBL"
        fingerprint = "v1_sha256_18e15b8a417f9ff2fd9277a01eb3224c761807ce9541ece568f4525ae66eb81f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 8B 45 D8 66 89 50 04 48 8B 45 D8 0F B7 40 02 66 D1 E8 0F }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_678c1145 {
    meta:
        id = "5aPrMvIb4kSSroopL7AxMK"
        fingerprint = "v1_sha256_5ff15c8d92bca62700bbb67aeebc41fd603687dbc0c93733955bf59375df40a1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "559793b9cb5340478f76aaf5f81c8dbfbcfa826657713d5257dac3c496b243a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C8 48 BA AB AA AA AA AA AA AA AA 48 89 C8 48 F7 E2 48 C1 EA 05 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_3cbdfb1f {
    meta:
        id = "1Zp4LqdwP6dY35stMCObxi"
        fingerprint = "v1_sha256_38e8ca59bf55c32b99aa76a89f60edcf09956b7cad0b4745fab92eca327c52db"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bd40ac964f3ad2011841c7eb4bf7cab332d4d95191122e830ab031dc9511c079"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 5B 53 54 44 32 2E 43 20 42 59 20 53 54 41 43 4B 44 5D 20 53 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_8b63ff02 {
    meta:
        id = "1Xb4nOVMrPg2BLwMQExDrF"
        fingerprint = "v1_sha256_3b68353c8eeb21a3eba7a02ae76b66b4f094ec52d5309582544d247cc6548da3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { DC 02 83 7D DC 01 0F 9F C0 84 C0 75 DF 83 7D DC 01 75 1D 66 C7 45 F6 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_30973084 {
    meta:
        id = "6YEbqllGtbWXwuVtacsrNU"
        fingerprint = "v1_sha256_d965a032c0fb6020c6187aa3117f7251dd8c9287c45453e3d5ae2ac62b3067bb"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "a22ffa748bcaaed801f48f38b26a9cfdd5e62183a9f6f31c8a1d4a8443bf62a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4C 69 73 74 20 49 6D 70 6F 72 74 20 46 6F 72 20 53 6F 75 72 63 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1cfa95dd {
    meta:
        id = "6ztfdAKykYNFdGBZm9OJW5"
        fingerprint = "v1_sha256_f73a96cc379c8dc060bfe5668ef7e47c5bcd037b3f41c300ef20c2f2f653cb00"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 7D EC 00 7E 0F 48 8B 45 F0 0F B6 00 0F B6 C0 48 01 C3 EB 10 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_25c48456 {
    meta:
        id = "7BjMsRxb0pa6hSS8lAnIeQ"
        fingerprint = "v1_sha256_4ed4b901fccaed834b9908fb447da1521bf31f283ae55b6d8f6090814cf8fcd2"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "eba6f3e4f7b53e22522d82bdbdf5271c3fc701cbe07e9ecb7b4c0b85adc9d6b4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 F8 48 83 6D E0 01 48 83 7D E0 00 75 DD 48 8B 45 F0 C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_b1ca2abd {
    meta:
        id = "6Gfm2kWttM9P4Q3F5AXgEH"
        fingerprint = "v1_sha256_05b906a9823bf9ba25ba1ed490beb8f338429cbc744ca230c5c4cbb41ab9f140"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 B0 C7 45 AC 14 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_cce8c792 {
    meta:
        id = "7kufTxYkuHmYXESLob1TYq"
        fingerprint = "v1_sha256_14700d24e8682ec04f2aae02f5820c4d956db60583b1bc61038b47e709705d0d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 48 89 51 08 48 8B 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_4bcea1c4 {
    meta:
        id = "26DjXVr6bxe7n8oXkG0xRO"
        fingerprint = "v1_sha256_76019729a3a33fc04ff983f38b4fbf174a66da7ffc05cd07eb93e3cd5aecaaa2"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 50 FF 48 8B 45 C0 48 01 D0 0F B6 00 3C 0A 74 22 48 8B 45 C0 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_ab561a1b {
    meta:
        id = "1mziAn4kcvNYz6nbayBofA"
        fingerprint = "v1_sha256_5720d2ada4b33514f2d528417876606d2951786df8b0512f9e8833b8ec87127a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1b7df0d491974bead05d04ede6cf763ecac30ecff4d27bb4097c90cc9c3f4155"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B5 50 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 83 BD 5C FF FF }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1a4eb229 {
    meta:
        id = "1WzV9SrftOvUXc0rbndSs6"
        fingerprint = "v1_sha256_83b04e366a05a46ad67b9aaf6b9658520e119003cd65941dd69416cbc5229c30"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F4 8B 45 E8 83 C0 01 89 45 F8 EB 0F 8B 45 E8 83 C0 01 89 45 F4 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_51ef0659 {
    meta:
        id = "3RxYnn3XwU3GKPGFuTp5UI"
        fingerprint = "v1_sha256_26dd95cb1cdaec10d408e294a3baca85d741cf5e56649cdcc79ef7216e4cb440"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "b7a2bc75dd9c44c38b2a6e4e7e579142ece92a75b8a3f815940c5aa31470be2b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E0 03 48 89 45 B0 8B 45 9C 48 63 D0 48 83 EA 01 48 89 55 B8 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_d90c4cbe {
    meta:
        id = "5h2exmnhAJg29ZVpRVYFff"
        fingerprint = "v1_sha256_145d32f8a06af18e6f13b0905cc51fd7b1a9e00b41b0f0a5d537ada2b54a94b5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 D8 F7 D0 5B 5D C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 48 89 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_c680c9fd {
    meta:
        id = "kaYXdakPUj4Bg0DiaTtBO"
        fingerprint = "v1_sha256_a283132ffdd109b8b1f01e5a3e2700b70b742945c7ae8b15b2b244fb249a5e3d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 01 D0 48 8D 48 10 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_e63396f4 {
    meta:
        id = "2U3uFCJPOUVNVhX4qkrRtK"
        fingerprint = "v1_sha256_d3f7c62a7411caf86ee574a686b4b1972066602f89d39ae9e49ba66d9917c7c9"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "913e6d2538bd7eed3a8f3d958cf445fe11c5c299a70e5385e0df6a9b2f638323"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 02 83 45 FC 01 81 7D FC FF 0F 00 00 7E ?? 90 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_7d5355da {
    meta:
        id = "AlAcjgJhzEtdNonRwAZN0"
        fingerprint = "v1_sha256_b4540f941ca1a36c460d056ef263ebd67c6388f3f6f373f50371f7cca2739bc4"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "03397525f90c8c2242058d2f6afc81ceab199c5abcab8fd460fabb6b083d8d20"
        threat_name = "Linux.Hacktool.Flooder"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E5 48 83 EC 60 64 48 8B 04 25 28 00 00 00 48 89 45 F8 31 C0 BF 0A 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a9e8a90f {
    meta:
        id = "mc9tjzX0aoEbjr9tUTbr6"
        fingerprint = "v1_sha256_8f1fcb736a9363142a25426ef2d166f92526bffaf8069f1b12056c9cf5825379"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "0558cf8cab0ba1515b3b69ac32975e5e18d754874e7a54d19098e7240ebf44e4"
        threat_name = "Linux.Hacktool.Flooder"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 D8 48 89 45 F0 66 C7 45 EE 00 00 EB 19 48 8B 45 F0 48 8D }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a598192a {
    meta:
        id = "1Bh1bKx752GP4hGpPba5u2"
        fingerprint = "v1_sha256_19909f53acca8c84125c95fc651765a25162c5f916366da8351e67675393e583"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
        threat_name = "Linux.Hacktool.Flooder"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8D 65 D8 5B 5E 5F C9 C3 8D 36 55 89 E5 83 EC 18 57 56 53 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_53bf4e37 {
    meta:
        id = "7hq30SHWWAr1DxCMnyU37u"
        fingerprint = "v1_sha256_d1aabf8067b74dac114e197722d51c4bbb9a78e6ba9b5401399930c29d55bdcc"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
        threat_name = "Linux.Hacktool.Flooder"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 00 49 50 5F 48 44 52 49 4E 43 4C 00 57 68 61 74 20 74 68 65 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_50158a6e {
    meta:
        id = "1EYNVJprmFQvUu6RJ62SVB"
        fingerprint = "v1_sha256_67c22fcf514a3e8c2c27817798c796aacf00ba82e1090894aa2c1170a1e2a096"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "1e0cdb655e48d21a6b02d2e1e62052ffaaec9fdfe65a3d180fc8afabc249e1d8"
        threat_name = "Linux.Hacktool.Flooder"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 F8 48 01 D0 48 89 45 D8 0F B7 45 E6 48 8D 50 33 48 8B 45 F8 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_f454ec10 {
    meta:
        id = "6hSvISlWxefncmquq3TrvN"
        fingerprint = "v1_sha256_e5afb215632ad6359ba95df86316d496ea5e36edb79901c34e0710a6bd9c97d1"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "0297e1ad6e180af85256a175183102776212d324a2ce0c4f32e8a44a2e2e9dad"
        threat_name = "Linux.Hacktool.Flooder"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 45 EC 48 63 D0 48 8B 45 D0 48 01 D0 0F B6 00 3C 2E 75 4D 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_9417f77b {
    meta:
        id = "AAxF4ztCPe5nBxjnTmQGg"
        fingerprint = "v1_sha256_470b7e44cd875b1f6abcfa5e4d33d2808a65630dc914b38643c9efb14db5f1ff"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "60ff13e27dad5e6eadb04011aa653a15e1a07200b6630fdd0d0d72a9ba797d68"
        threat_name = "Linux.Hacktool.Flooder"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0F B7 45 F6 0F B7 C0 48 01 C3 48 89 DA 48 C1 FA 10 0F B7 C3 48 8D }
    condition:
        all of them
}

