rule Windows_VulnDriver_HrSword_15b431ee {
    meta:
        id = "6QsE2n1IQvzUtWYxlgyseo"
        fingerprint = "v1_sha256_d8aed70f101a717efe83adceea0f220fb0b145ab8aa39b6250ac2bc057bf51ce"
        version = "1.0"
        date = "2023-05-25"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.HrSword"
        reference_sample = "272e934cec4a84ab92b2bccb98539d73542ea9184960a2c9923d4edc667f4d4f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 79 00 73 00 64 00 69 00 61 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $str1 = "Huorong Internet Security Core Kext" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $str1
}

