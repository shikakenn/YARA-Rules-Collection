rule Linux_Trojan_Ebury_7b13e9b6 {
    meta:
        id = "6zRCofNPnBM3ksxX9DcC7M"
        fingerprint = "v1_sha256_30d126ffc5b782236663c23734f1eef21e1cc929d549a37bba8e1e7b41321111"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ebury"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 44 24 10 4C 8B 54 24 18 4C 8B 5C 24 20 8B 5C 24 28 74 04 }
    condition:
        all of them
}

