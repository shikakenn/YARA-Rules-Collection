rule Linux_Trojan_Zpevdo_7f563544 {
    meta:
        id = "7iBSqGzmAQffYLdgfkBfqF"
        fingerprint = "v1_sha256_9cbbb5a9166184cef630d1aba8fec721f676b868d22b1f96ffc1430e98ae974c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Zpevdo"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 48 89 E5 48 83 EC 20 89 7D EC 48 89 75 E0 BE 01 00 00 00 BF 11 00 }
    condition:
        all of them
}

