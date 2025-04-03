rule Linux_Hacktool_Bruteforce_bad95bd6 {
    meta:
        id = "5lDWjVMbN2UBXclSwUKwg4"
        fingerprint = "v1_sha256_8001e6503baeb52c66c9b30026544913270085406a1fe4c45d14629811d36d5f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "8e8be482357ebddc6ac3ea9ee60241d011063f7e558a59e6bd119e72e4862024"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 73 65 6E 64 6D 6D 73 67 00 66 70 75 74 73 00 6D 65 6D 63 70 79 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Bruteforce_66a14c03 {
    meta:
        id = "2GPLBbYybV8No6epAN4cUs"
        fingerprint = "v1_sha256_c8b2925c2e3f95e78f117ddd52e208d143d19ee75e9283f7f15d10e930eaac5f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "a2d8e2c34ae95243477820583c0b00dfe3f475811d57ffb95a557a227f94cd55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 8B 4C 24 08 78 3D 48 8B 44 24 30 48 29 C8 48 89 4D 08 48 89 }
    condition:
        all of them
}

rule Linux_Hacktool_Bruteforce_eb83b6aa {
    meta:
        id = "4qBiQ8ljqMZOOb0T6uylsb"
        fingerprint = "v1_sha256_bc79860e414d07ee8000eea3d61827272d66faa90a8bf6c65fcda90a4bd762ef"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "8dec88576f61f37fbaece3c30e71d338c340c8fb9c231f9d7b1c32510d2c3167"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 89 45 EC EB 04 83 6D EC 01 83 7D EC 00 74 12 8B 45 EC 8D }
    condition:
        all of them
}

