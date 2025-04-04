rule Windows_Trojan_Pingpull_09dd9559 {
    meta:
        id = "6GX8gAdF8lcVisYoKmLwKn"
        fingerprint = "v1_sha256_114674b1a9acfc7643138d3b07885343a50c9d319b8d22a6ef34e916685c4469"
        version = "1.0"
        date = "2022-06-16"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Pingpull"
        reference_sample = "de14f22c88e552b61c62ab28d27a617fb8c0737350ca7c631de5680850282761"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "PROJECT_%s_%s_%08X" ascii fullword
        $s2 = "Iph1psvc" ascii fullword
        $s3 = "IP He1per" ascii fullword
        $s4 = "If this service is stopped, the computer will not have the enhanced connectivity benefits that these technologies offer."
        $a1 = { 02 C? 66 C7 44 24 ?? 3A 00 4C 8D 44 24 ?? 88 4C 24 ?? 48 83 C9 FF 88 44 24 ?? F2 AE 33 ?? 0F 1F }
        $a2 = { 48 85 FF 74 ?? 41 C1 E0 04 0F B6 4C 3C ?? 33 D2 8D 41 ?? ?? 19 77 ?? 80 C1 E0 8D 41 ?? 3C 09 77 }
        $a3 = { 4C 63 74 24 ?? 48 8B ?? 43 8D 44 36 ?? 4C 63 E8 49 8B CD E8 ?? ?? ?? ?? 48 8B ?? 48 85 C0 0F 84 }
    condition:
        3 of them
}

