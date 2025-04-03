rule Linux_Shellcode_Generic_5669055f {
    meta:
        id = "LBStANItX8LD4ObPrOeU5"
        fingerprint = "v1_sha256_735b8dc7fff3c9cc96646a4eb7c5afd70be19dcc821e9e26ce906681130746be"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "87ef4def16d956cdfecaea899cbb55ff59a6739bbb438bf44a8b5fec7fcfd85b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 51 B1 06 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_d2c96b1d {
    meta:
        id = "5jK8t2cThDq5XjO0DZgSLw"
        fingerprint = "v1_sha256_33d964e22c8e3046f114e8264d18e8b4a0e7b55eca59151b084db7eea07aa0b1"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "403d53a65bd77856f7c565307af5003b07413f2aba50869655cdd88ce15b0c82"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E1 8D 54 24 04 5B B0 0B CD 80 31 C0 B0 01 31 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_30c70926 {
    meta:
        id = "3logmIK0MhdZGsC959FPMr"
        fingerprint = "v1_sha256_3594994a911e5428198c472a51de189a6be74895170581ec577c49f8dbb9167a"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "a742e23f26726293b1bff3db72864471d6bb4062db1cc6e1c4241f51ec0e21b1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E3 52 53 89 E1 31 C0 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_224bdcc4 {
    meta:
        id = "1pJiCcj5JvZ4MdaQoNSyyh"
        fingerprint = "v1_sha256_8c4a2bb63f0926e7373caf0a027179b4730cc589f9af66d2071e88f4165b0f73"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "bd22648babbee04555cef52bfe3e0285d33852e85d254b8ebc847e4e841b447e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E6 6A 10 5A 6A 2A 58 0F 05 48 85 C0 79 1B 49 FF C9 74 22 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_99b991cd {
    meta:
        id = "5d6vilud9GX9ImcaIsNufc"
        fingerprint = "v1_sha256_664e213314fe1d6f1920de237ebea3a94f7fbc42eff089475674ccef812f0f68"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "954b5a073ce99075b60beec72936975e48787bea936b4c5f13e254496a20d81d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6E 89 E3 50 53 89 E1 B0 0B CD 80 00 4C 65 6E 67 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_24b9aa12 {
    meta:
        id = "6i3d9Z8xa7JqTy8Z9aXgOq"
        fingerprint = "v1_sha256_4685253eb00a21d6dd6e874ff68209f20c8668262f24767086687555ccf934aa"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "24b2c1ccbbbe135d40597fbd23f7951d93260d0039e0281919de60fa74eb5977"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6E 89 E3 89 C1 89 C2 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_8ac37612 {
    meta:
        id = "6NeRB9H7FXmuMy9yxHo3PZ"
        fingerprint = "v1_sha256_c0af751bc54dcd9cf834fa5fe9fa120be5e49a56135ebb72fd6073948e956929"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "c199b902fa4b0fcf54dc6bf3e25ad16c12f862b47e055863a5e9e1f98c6bd6ca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E3 ?? 53 89 E1 B0 0B CD 80 00 47 43 43 3A }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_932ed0f0 {
    meta:
        id = "4z3gH1yVaaxh6qxP1sJvpG"
        fingerprint = "v1_sha256_20ae3f1d96f8afd0900ac919eacaff3bd748a7466af5bb2b9f77cfdc4b8b829e"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "f357597f718f86258e7a640250f2e9cf1c3363ab5af8ddbbabb10ebfa3c91251"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E3 50 89 E2 53 89 E1 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

