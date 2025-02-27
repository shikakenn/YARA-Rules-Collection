rule Linux_Trojan_Sdbot_98628ea1 {
    meta:
        id = "11yDYv5KRBSGFmFGsquRHe"
        fingerprint = "v1_sha256_55b8e3fa755965b85a043015f9303644b8e06fe8bfdc0e2062de75bdc2881541"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sdbot"
        reference_sample = "5568ae1f8a1eb879eb4705db5b3820e36c5ecea41eb54a8eef5b742f477cbdd8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 00 3C 08 54 00 02 00 26 00 00 40 4D 08 00 5C 00 50 00 49 00 }
    condition:
        all of them
}

