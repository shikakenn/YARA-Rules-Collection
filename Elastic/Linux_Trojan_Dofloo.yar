rule Linux_Trojan_Dofloo_be1973ed {
    meta:
        id = "48sdC6irvtgfv7kZ4UypM0"
        fingerprint = "v1_sha256_65f9daabf44006fe4405032bf93570185248bc62cd287650c68f854b23aa2158"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { A8 8B 45 A8 89 45 A4 83 7D A4 00 79 04 83 45 A4 03 8B 45 A4 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Dofloo_1d057993 {
    meta:
        id = "3CCeM8aWhxAFxVSmypXQ03"
        fingerprint = "v1_sha256_c5e15e21946816052d5a8dc293db3830f1d6d06cdbf22eb8667b655206dbbc1f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 88 45 DB 83 EC 04 8B 45 F8 83 C0 03 89 45 D4 8B 45 D4 89 }
    condition:
        all of them
}

rule Linux_Trojan_Dofloo_29c12775 {
    meta:
        id = "21DBFMVhw293BeDHt6xHBM"
        fingerprint = "v1_sha256_a8eb79fdf57811f4ffd5a7c5ec54cf46c06281f8cd4d677aec1ad168d6648a08"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 2F 7E 49 00 64 80 49 00 34 7F 49 00 04 7F 49 00 24 80 49 }
    condition:
        all of them
}

