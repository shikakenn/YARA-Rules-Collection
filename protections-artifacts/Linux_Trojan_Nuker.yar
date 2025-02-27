rule Linux_Trojan_Nuker_12f26779 {
    meta:
        id = "4XWYQc3abs0YkPFHCWEm8w"
        fingerprint = "v1_sha256_8bafbc2792bd4cacd309efd72d2d8787342685d66785ea41cb57c91519a3c545"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Nuker"
        reference_sample = "440105a62c75dea5575a1660fe217c9104dc19fb5a9238707fe40803715392bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C4 18 89 45 D8 83 7D D8 FF 75 17 68 ?? ?? 04 08 }
    condition:
        all of them
}

