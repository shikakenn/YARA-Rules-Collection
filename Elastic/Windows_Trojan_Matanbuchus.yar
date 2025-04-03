rule Windows_Trojan_Matanbuchus_b521801b {
    meta:
        id = "7ZdouWgAHTi2lL8DdXZ51E"
        fingerprint = "v1_sha256_609a0941b118d737124a5cd9c98c007e21557a239cfa3cf97cd3b4348c934f03"
        version = "1.0"
        date = "2022-03-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Matanbuchus"
        reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%PROCESSOR_ARCHITECTURE%" ascii fullword
        $a2 = "%PROCESSOR_REVISION%\\" ascii fullword
        $a3 = "%LOCALAPPDATA%\\" ascii fullword
        $a4 = "\"C:\\Windows\\system32\\schtasks.exe\" /Create /SC MINUTE /MO 1 /TN" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Matanbuchus_4ce9affb {
    meta:
        id = "4H6qaVk9w9fKYX6U1mhjMp"
        fingerprint = "v1_sha256_16441eb4617b6b3cb1e7d600959a5cbfe15c72c00361b45551b7ef4c81f78462"
        version = "1.0"
        date = "2022-03-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Matanbuchus"
        reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { F4 83 7D F4 00 77 43 72 06 83 7D F0 11 73 3B 6A 00 6A 01 8B }
    condition:
        all of them
}

rule Windows_Trojan_Matanbuchus_58a61aaa {
    meta:
        id = "5lTsgwzKh9b2fBjs9ffjjp"
        fingerprint = "v1_sha256_7226e2f61bd6f1cca15c1f3f8d8697cb277d1e214f756295ffda5bc16304cc49"
        version = "1.0"
        date = "2022-03-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Matanbuchus"
        reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 83 EC 08 53 56 0F 57 C0 66 0F 13 45 F8 EB ?? 8B 45 F8 83 C0 01 8B 4D FC 83 D1 00 89 45 F8 89 4D FC 8B 55 FC 3B 55 }
    condition:
        all of them
}

rule Windows_Trojan_Matanbuchus_c7811ccc {
    meta:
        id = "752pktGP9tQhacp3sk8Atz"
        fingerprint = "v1_sha256_e65dc05f6d9289a42c05afdc4da0ce1c18c1129dd87688a277ece925e83d7ef1"
        version = "1.0"
        date = "2022-03-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Matanbuchus"
        reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 83 EC 08 53 56 0F 57 C0 66 0F 13 45 F8 EB ?? 8B 45 F8 83 C0 01 8B 4D FC 83 D1 00 89 45 F8 89 4D FC 8B 55 FC 3B 55 10 77 ?? 72 ?? 8B 45 F8 3B 45 0C 73 ?? 6A 00 6A 08 8B 4D FC 51 8B 55 F8 52 E8 ?? ?? ?? ?? 6A 00 6A 08 52 50 E8 ?? ?? ?? ?? 8B C8 8B 45 14 8B 55 18 E8 ?? ?? ?? ?? 0F BE F0 6A 00 6A 01 8B 55 FC 52 8B 45 F8 50 E8 ?? ?? ?? ?? 8B 4D 08 0F BE 1C 01 33 DE 6A 00 6A 01 8B 55 FC 52 8B 45 F8 50 E8 ?? ?? ?? ?? 8B 4D 08 88 1C 01 E9 ?? ?? ?? ?? 5E 5B 8B E5 5D C2 14 00 }
    condition:
        all of them
}

