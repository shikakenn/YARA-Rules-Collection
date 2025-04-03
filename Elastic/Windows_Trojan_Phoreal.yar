rule Windows_Trojan_Phoreal_66e91de3 {
    meta:
        id = "5mC10GIIL9oRXfOgL7nZlj"
        fingerprint = "v1_sha256_c68131fd5e0272d3d473db387a186056a38e6611925ae448d5b668022e6e163a"
        version = "1.0"
        date = "2022-02-16"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/phoreal-malware-targets-the-southeast-asian-financial-sector"
        threat_name = "Windows.Trojan.Phoreal"
        reference_sample = "88f073552b30462a00d1d612b1638b0508e4ef02c15cf46203998091f0aef4de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 7B 00 41 00 30 00 36 00 46 00 31 00 37 00 36 00 46 00 2D 00 37 00 39 00 46 00 31 00 2D 00 34 00 37 00 33 00 45 00 2D 00 41 00 46 00 34 00 34 00 2D 00 39 00 37 00 36 00 33 00 45 00 33 00 43 00 42 00 33 00 34 00 45 00 35 00 7D 00 }
        $a2 = { 4C 00 6F 00 63 00 61 00 6C 00 5C 00 7B 00 35 00 46 00 42 00 43 00 33 00 46 00 35 00 33 00 2D 00 41 00 37 00 36 00 44 00 2D 00 34 00 32 00 34 00 38 00 2D 00 39 00 36 00 39 00 41 00 2D 00 33 00 31 00 37 00 34 00 30 00 43 00 42 00 43 00 38 00 41 00 44 00 36 00 7D 00 }
        $a3 = { 7B 46 44 35 46 38 34 34 37 2D 36 35 37 41 2D 34 35 43 31 2D 38 39 34 42 2D 44 35 33 33 39 32 36 43 39 42 36 36 7D 2E 64 6C 6C }
        $b1 = { 8B FF 55 8B EC 56 E8 3F 3E 00 00 E8 34 3E 00 00 50 E8 14 3E 00 00 85 C0 75 2A 8B 75 08 56 E8 21 }
    condition:
        2 of them
}

