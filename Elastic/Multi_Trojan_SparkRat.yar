rule Multi_Trojan_SparkRat_9a21e541 {
    meta:
        id = "4K9fUczyRPYr5QKaIpqTlp"
        fingerprint = "v1_sha256_903c5c65436bea8dd044fd5f1f6dda3d1e90ab25802d508f67ba0f7fd06e92d4"
        version = "1.0"
        date = "2023-11-13"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Trojan.SparkRat"
        reference_sample = "23efecc03506a9428175546a4b7d40c8a943c252110e83dec132c6a5db8c4dd6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "Spark/client/service/file" ascii wide
        $a2 = "Spark/client/service/desktop" ascii wide
        $a3 = "Spark/utils.Encrypt" ascii wide
    condition:
        all of them
}

