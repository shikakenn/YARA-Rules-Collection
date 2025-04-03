rule Windows_Trojan_GuidLoader_d3a30cec {
    meta:
        id = "7zmVttN14LUsMo3ug8gTW"
        fingerprint = "v1_sha256_62b4f787fbd2eef3639887eb380b052f6ddde3abfb66302a898539f8efe7aa8f"
        version = "1.0"
        date = "2025-01-10"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.GuidLoader"
        reference_sample = "f90420847e1f2378ac8c52463038724533a9183f02ce9ad025a6a10fd4327f12"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $seq1 = { 75 ?? B9 88 13 00 00 FF 15 ?? ?? ?? ?? 48 FF C? 48 83 F? }
        $seq2 = { 48 8B 55 ?? 48 83 FA 10 72 ?? 48 FF C2 48 8B 4D ?? 48 8B C1 48 81 FA 00 10 00 00 }
        $seq3 = { C1 E8 ?? 03 D0 0F BE C2 6B C8 ?? 41 0F B6 C0 41 FF C0 2A C1 04 ?? 41 30 41 ?? 41 83 F8 ?? 7C ?? }
        $seq4 = { 66 0F DB 15 ?? ?? 00 00 66 0F 67 D2 66 0F FC 15 ?? ?? 00 00 66 0F EF D0 66 0F 62 CB }
        $seq5 = "Download" ascii fullword
    condition:
        4 of them
}

