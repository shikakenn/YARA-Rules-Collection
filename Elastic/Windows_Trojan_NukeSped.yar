rule Windows_Trojan_NukeSped_b8e6cc07 {
    meta:
        id = "5KXqzktMTcb9fup4XnEFq5"
        fingerprint = "v1_sha256_f0bbb92acb74c9c10161a4f3c318042a2ec75b62b65bd9b904175dea071e48a0"
        version = "1.0"
        date = "2024-12-31"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.NukeSped"
        reference_sample = "2dff6d721af21db7d37fc1bd8b673ec07b7114737f4df2fa8b2ecfffbe608a00"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str_0 = "8877 Success!" ascii fullword
        $str_1 = "8888 Success!" ascii fullword
        $str_2 = "1234 Success!" ascii fullword
        $str_3 = "1111%d Success!" ascii fullword
        $str_4 = "4444OK" ascii fullword
        $str_5 = { 40 65 63 68 6F 20 6F 66 66 0D 0A 3A 4C 31 0D 0A 64 65 6C 20 22 25 73 22 25 73 20 22 25 73 22 20 67 6F 74 6F 20 4C 31 0D 0A 64 65 6C 20 22 25 73 22 0D 0A 00 }
    condition:
        4 of them
}

