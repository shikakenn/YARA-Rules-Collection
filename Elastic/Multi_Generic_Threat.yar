rule Multi_Generic_Threat_19854dc2 {
    meta:
        id = "2ua18dG7ufwvBTntMXLJWE"
        fingerprint = "v1_sha256_beed6d6cd7b7b6eb3f4ab6a45fd19f2ebfb661e470d468691b68634994e2eef7"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Generic.Threat"
        reference_sample = "be216fa9cbf0b64d769d1e8ecddcfc3319c7ca8e610e438dcdfefc491730d208"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = { 26 2A 73 74 72 75 63 74 20 7B 20 45 6E 74 72 79 53 61 6C 74 20 5B 5D 75 69 6E 74 38 3B 20 4C 65 6E 20 69 6E 74 20 7D }
    condition:
        all of them
}

