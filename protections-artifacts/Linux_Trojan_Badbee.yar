rule Linux_Trojan_Badbee_231cb054 {
    meta:
        id = "7duW1NRRksRulaBu0cVMAa"
        fingerprint = "v1_sha256_a1ed8f2da9b4f891a5c65d943424bb7c465f0d07e7756e292c617ce5ef14d182"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Badbee"
        reference_sample = "832ba859c3030e58b94398ff663ddfe27078946a83dcfc81a5ef88351d41f4e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8D B4 41 31 44 97 10 83 F9 10 75 E4 89 DE C1 FE 14 F7 C6 01 00 }
    condition:
        all of them
}

