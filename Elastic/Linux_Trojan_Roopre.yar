rule Linux_Trojan_Roopre_b6b9e71d {
    meta:
        id = "afoW9Og0NzBsFPT7iwufW"
        fingerprint = "v1_sha256_32294e476a014a919d2d738bdc940a7fc5f91e1b13c005f164a5b6bf84eb2635"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Roopre"
        reference_sample = "36ae2bf773135fdb0ead7fbbd46f90fd41d6f973569de1941c8723158fc6cfcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 24 08 48 C7 C6 18 FC FF FF 49 8B 4A 08 48 89 C8 48 99 48 }
    condition:
        all of them
}

rule Linux_Trojan_Roopre_05f7f237 {
    meta:
        id = "4OJHH01Cvvx9zeV2kIRtLo"
        fingerprint = "v1_sha256_12e14ac31932033f2448b7a3bfd6ce826fff17494547ac4baefb20f6713baf5f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Roopre"
        reference_sample = "36ae2bf773135fdb0ead7fbbd46f90fd41d6f973569de1941c8723158fc6cfcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 01 3A 74 06 80 7F 02 5C 75 1F 48 83 C7 03 B2 5C EB E8 38 D1 48 8D }
    condition:
        all of them
}

