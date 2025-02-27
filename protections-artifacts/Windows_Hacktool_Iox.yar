rule Windows_Hacktool_Iox_98cd1cd8 {
    meta:
        id = "6li8Th07ZNL91CbhJsSB5x"
        fingerprint = "v1_sha256_d7f9e4f399410d54416e974fbd66b2caa27359ae0f2e33e01d62f1aa618daa34"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-01-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        threat_name = "Windows.Hacktool.Iox"
        reference_sample = "d4544a521d4e6eb07336816b1aae54f92c5c4fd2eb31dcfbdf26e4ef890e73db"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $param_check_b0 = { 48 83 FB 05 0F 85 ?? ?? ?? ?? 81 38 70 72 6F 78 66 0F 1F 44 00 00 0F 85 ?? ?? ?? ?? 80 78 04 79 0F 85 ?? ?? ?? ?? 48 83 F9 03 }
        $param_check_b1 = { 48 8B 14 24 4C 8B 5C 24 18 4C 8B 64 24 08 4C 8B 6C 24 08 4C 8B 7C 24 20 66 0F 1F 84 00 00 00 00 00 48 83 FB 03 0F 85 ?? ?? ?? ?? 66 81 38 66 77 0F 85 ?? ?? ?? ?? 80 78 02 64 }
        $param_check_b2 = { 81 38 2D 2D 6C 6F 0F 1F 44 00 00 0F 85 ?? ?? ?? ?? 66 81 78 04 63 61 0F 85 ?? ?? ?? ?? 80 78 06 6C }
        $param_check_b3 = { 83 FA 05 0F 85 ?? ?? ?? ?? 81 38 2D 2D 6B 65 0F 85 ?? ?? ?? ?? 80 78 04 79 90 }
    condition:
        3 of them
}

