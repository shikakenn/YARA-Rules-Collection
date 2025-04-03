rule Linux_Trojan_Swrort_5ad1a4f9 {
    meta:
        id = "UvBbM7tTWSQnsf8Lnt6tq"
        fingerprint = "v1_sha256_3a1fa978e0c8ab0dd4e7965a3f91306d6123c19f21b86d3f8088979bf58c3a07"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "fa5695c355a6dc1f368a4b36a45e8f18958dacdbe0eac80c618fbec976bac8fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 53 57 68 B7 E9 38 FF FF D5 53 53 57 68 74 EC 3B E1 FF D5 57 }
    condition:
        all of them
}

rule Linux_Trojan_Swrort_4cb5b116 {
    meta:
        id = "3WkmQvtvv0BdTr6g5234ew"
        fingerprint = "v1_sha256_9404856fc3290f3a8f9bf891fde9a614fc4484719eb3b51ce7ab601a41e0c3a5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "703c16d4fcc6f815f540d50d8408ea00b4cf8060cc5f6f3ba21be047e32758e0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 04 6A 10 89 E1 6A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Swrort_22c2d6b6 {
    meta:
        id = "1lNJskX0Uh1lCuR5JeBBIq"
        fingerprint = "v1_sha256_f661544d267a55feec786ab3d4fc4f002afa8e2b58833461f56b745ec65acfd4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "6df073767f48dd79f98e60aa1079f3ab0b89e4f13eedc1af3c2c073e5e235bbc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 51 6A 04 54 6A 02 }
    condition:
        all of them
}

