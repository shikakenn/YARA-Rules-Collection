rule Linux_Trojan_Kaiji_253c44de {
    meta:
        id = "Jy0WXYivUMtt6v0gGFkhz"
        fingerprint = "v1_sha256_81a07f60765f50c58b2c0f0153367ee570f36c579e9f88fb2f0e49ae5c08773f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "e31eb8880bb084b4c642eba127e64ce99435ea8299a98c183a63a2e6a139d926"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EB 27 0F B6 1C 10 48 8B 74 24 40 48 8B BC 24 90 00 00 00 88 }
    condition:
        all of them
}

rule Linux_Trojan_Kaiji_535f07ac {
    meta:
        id = "5vrQHcE3Yd2vb4ZefxJgN7"
        fingerprint = "v1_sha256_539977c1076b71873135cfe02153da87c0e9ac17122f04570977a22c92d2694f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "28b2993d7c8c1d8dfce9cd2206b4a3971d0705fd797b9fde05211686297f6bb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 44 24 10 48 8B 4C 24 08 48 83 7C 24 18 00 74 26 C6 44 24 57 00 48 8B 84 24 98 00 }
    condition:
        all of them
}

rule Linux_Trojan_Kaiji_dcf6565e {
    meta:
        id = "1XzFWB4QGB882q8oNA04v7"
        fingerprint = "v1_sha256_2bc943e100548e9aacd97930b3230353be760c8a292dbbbd1d0b5646f647c4fe"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "49f3086105bdc160248e66334db00ce37cdc9167a98faac98800b2c97515b6e7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 69 D2 9B 00 00 00 48 C1 EA 20 83 C2 64 48 8B 9C 24 B8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Kaiji_91091be3 {
    meta:
        id = "4sABOyoIrpLhwVHbZ4GBre"
        fingerprint = "v1_sha256_3b55cb3be5775311af4dc90f9624448d30cc58ef1a42729f6ca4eb3b36ad8b06"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "dca574d13fcbd7d244d434fcbca68136e0097fefc5f131bec36e329448f9a202"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 18 83 7C 24 1C 02 75 9E 8B 4C 24 64 8B 51 1C 89 54 24 5C }
    condition:
        all of them
}

