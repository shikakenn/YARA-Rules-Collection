rule Linux_Trojan_Truncpx_894d60f8 {
    meta:
        id = "6BopExcj6b1TZ7BxT6FLOU"
        fingerprint = "v1_sha256_9bc0a7fbddac532b53c72681f349bca0370b1fe6fb2d16f539560085b3ec4be3"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Truncpx"
        reference_sample = "2f09f2884fd5d3f5193bfc392656005bce6b935c12b3049ac8eb96862e4645ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B9 51 FE 88 63 A1 08 08 09 C5 1A FF D3 AB B2 28 }
    condition:
        all of them
}

