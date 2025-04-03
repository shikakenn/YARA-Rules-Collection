rule Windows_Trojan_Stealc_b8ab9ab5 {
    meta:
        id = "1QgOCmqzUIZYKv98TItBqa"
        fingerprint = "v1_sha256_5fc5d5cea481d1d204d1aa6c52679a23eb59438df2fe547d14c00524772867bb"
        version = "1.0"
        date = "2024-03-13"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $seq_str_decrypt = { 55 8B EC 83 EC ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 83 C0 ?? 50 }
        $seq_lang_check = { 81 E9 19 04 00 00 89 4D ?? 83 7D ?? ?? 77 ?? 8B 55 ?? 0F B6 82 ?? ?? ?? ?? FF 24 85 ?? ?? ?? ?? }
        $seq_mem_check_constant = { 72 09 81 7D F8 57 04 00 00 73 08 }
        $seq_hwid_algo = { 8B 08 69 C9 0B A3 14 00 81 E9 51 75 42 69 8B 55 08 }
        $str1 = "- Country: ISO?" ascii fullword
        $str2 = "%d/%d/%d %d:%d:%d" ascii fullword
        $str3 = "%08lX%04lX%lu" ascii fullword
        $str4 = "\\Outlook\\accounts.txt" ascii fullword
        $str5 = "/c timeout /t 5 & del /f /q" ascii fullword
    condition:
        (2 of ($seq*) or 4 of ($str*))
}

rule Windows_Trojan_Stealc_a2b71dc4 {
    meta:
        id = "3cmzSZ8j1PROPPcHK1sdqo"
        fingerprint = "v1_sha256_b79ac3e65cd7d2819d6a49f59ec661241c97174f66a7c4ada91932f10fc43583"
        version = "1.0"
        date = "2024-03-13"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "0d1c07c84c54348db1637e21260dbed09bd6b7e675ef58e003d0fe8f017fd2c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $seq_1 = { 8B C6 C1 E8 02 33 C6 D1 E8 33 C6 C1 E8 02 33 C6 83 E0 01 A3 D4 35 61 00 C1 E0 0F 66 D1 E9 66 0B C8 }
        $seq_2 = { FF D3 8B 4D ?? E8 [4] 6A ?? 33 D2 5F 8B C8 F7 F7 85 D2 74 ?? }
        $seq_3 = { 33 D2 8B F8 59 F7 F1 8B C7 3B D3 76 04 2B C2 03 C1 }
        $seq_4 = { 6A 7C 58 66 89 45 FC 8D 45 F0 50 8D 45 FC 50 FF 75 08 C7 45 F8 01 }
    condition:
        2 of ($seq*)
}

rule Windows_Trojan_Stealc_5d3f297c {
    meta:
        id = "7m8enBZCvf3c7Tuj0eMGpU"
        fingerprint = "v1_sha256_556d3bc9374a5ec23faa410900dfc94b5534434c9733165355d281976444a42b"
        version = "1.0"
        date = "2024-03-05"
        modified = "2024-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "885c8cd8f7ad93f0fd43ba4fb7f14d94dfdee3d223715da34a6e2fbb4d25b9f4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 08 C7 45 F8 00 00 00 00 83 7D 08 00 74 4A 83 7D 0C 00 74 44 8B 45 0C 83 C0 01 50 6A 40 ?? ?? ?? ?? ?? ?? 89 45 F8 83 7D F8 00 74 2C C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 }
    condition:
        all of them
}

