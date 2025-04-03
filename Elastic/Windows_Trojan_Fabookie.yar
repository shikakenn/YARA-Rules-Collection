rule Windows_Trojan_Fabookie_024f8759 {
    meta:
        id = "4N74biXjQTCvb8lA2njeHy"
        fingerprint = "v1_sha256_9477406b718c6489161cf4636be66c4f72df923b9c5a7ee4069ef6a9552de485"
        version = "1.0"
        date = "2023-06-22"
        modified = "2023-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Fabookie"
        reference_sample = "6c6345c6f0a5beadc4616170c87ec8a577de185d53345581e1b00e72af24c13e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 89 C2 4D 33 C0 4D 33 C9 C7 44 24 20 02 00 00 80 }
        $a2 = { C7 C2 80 84 1E 00 41 C7 C0 00 10 00 00 41 C7 C1 04 00 00 00 48 8B 44 24 }
    condition:
        all of them
}

