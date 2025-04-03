rule Windows_Trojan_LegionLoader_f91120c6 {
    meta:
        id = "khSmkn860tVJQ7NOEx8AM"
        fingerprint = "v1_sha256_760402587a9ca3d3e6602fe57d3346ea6f60ba5c8d3a902bf493233baab597b0"
        version = "1.0"
        date = "2024-06-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.LegionLoader"
        reference_sample = "45670ffa9b24542ae84e3c9eb5ce609c2bcd29129215a7f37eb74b6211e32b22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 83 EC 08 89 4D F8 8B 4D F8 E8 4F 01 00 00 0F B6 C0 85 C0 75 09 C7 45 FC 01 00 00 00 EB 07 C7 45 FC 00 00 00 00 0F B6 45 FC 8B E5 5D C3 55 8B EC 51 89 4D FC 8B 4D FC E8 21 01 00 00 8B }
    condition:
        all of them
}

