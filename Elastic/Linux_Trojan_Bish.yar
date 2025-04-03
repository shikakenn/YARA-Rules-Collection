rule Linux_Trojan_Bish_974b4b47 {
    meta:
        id = "a59d7vkqePaoz0nn7nOf1"
        fingerprint = "v1_sha256_c5a7d036c89fe50626da51486d19ee731ad28cbc8d36def075d8f33a7b68961f"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Bish"
        reference_sample = "9171fd2bbe182f0a3cd35937f3ee0076c9358f52f5bc047498dd9e233ae11757"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 50 68 6E }
    condition:
        all of them
}

