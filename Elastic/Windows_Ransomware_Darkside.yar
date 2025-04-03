rule Windows_Ransomware_Darkside_d7fc4594 {
    meta:
        id = "4TYgyYeMJU3cFNxekLSFvz"
        fingerprint = "v1_sha256_0083fb64955973e7dbbb35d08cb780fa0b4ff4d064c102dc8f86e29af8358bad"
        version = "1.0"
        date = "2021-05-20"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Darkside"
        reference_sample = "bfb31c96f9e6285f5bb60433f2e45898b8a7183a2591157dc1d766be16c29893"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5F 30 55 56 BD 0A 00 00 00 8B 07 8B 5F 10 8B 4F 20 8B 57 30 }
    condition:
        any of them
}

rule Windows_Ransomware_Darkside_aceac5d9 {
    meta:
        id = "5zR77nnoKV0ntORSHYNZFj"
        fingerprint = "v1_sha256_888ab06b55b07879ee6b9a45c04f1a09c570aeb4be55c698300566d57fd47252"
        version = "1.0"
        date = "2021-05-20"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Darkside"
        reference_sample = "bfb31c96f9e6285f5bb60433f2e45898b8a7183a2591157dc1d766be16c29893"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 41 54 55 53 48 83 EC 28 48 8B 1F 4C 8B 66 08 48 8D 7C 24 10 4C }
    condition:
        any of them
}

