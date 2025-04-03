rule Linux_Worm_Generic_920d273f {
    meta:
        id = "6e24OCDtvq9VVfSULPK739"
        fingerprint = "v1_sha256_d0ed260857ae3002483ea7ef242b82514caaa95c2700b39dd0a03d39fdde090d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "04a65bc73fab91f654d448b2d7f8f15ac782965dcdeec586e20b5c7a8cc42d73"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E9 E5 49 86 49 A4 1A 70 C7 A4 AD 2E E9 D9 09 F5 AD CB ED FC 3B }
    condition:
        all of them
}

rule Linux_Worm_Generic_98efcd38 {
    meta:
        id = "6bDhGZdmvq8k6wWd2q5Tds"
        fingerprint = "v1_sha256_c1a130d2ef8d09cb28adc4e347cbd1a083c78241752ecf3f935b03d774d00a81"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "87507f5cd73fffdb264d76db9b75f30fe21cc113bcf82c524c5386b5a380d4bb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 14 75 E1 8B 5A 24 01 EB 66 8B 0C 4B 8B 5A 1C 01 EB 8B 04 8B }
    condition:
        all of them
}

rule Linux_Worm_Generic_bd64472e {
    meta:
        id = "2Teqbpzx4NabglpLZaZhIz"
        fingerprint = "v1_sha256_9a7267a0ebc1073d0b1f81a61b963642cc816b563b43ff4d9508dd8bc195a0e1"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "b3334a3b61b1a3fc14763dc3d590100ed5e85a97493c89b499b02b76f7a0a7d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C0 89 45 EC 83 7D EC FF 75 38 68 54 90 04 08 }
    condition:
        all of them
}

rule Linux_Worm_Generic_3ff8f75b {
    meta:
        id = "lXm6cZhUwLrTM0xyP8ye9"
        fingerprint = "v1_sha256_798e98f286201f1cda18bf1bf433826cf8a949b584f016b24a684425069d1024"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "991175a96b719982f3a846df4a66161a02225c21b12a879e233e19124e90bd35"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 3A DF FE 00 66 0F 73 FB 04 66 0F 6F D3 66 0F EF D9 66 0F 6F EE 66 0F 70 }
    condition:
        all of them
}

