rule Windows_Trojan_XWorm_732e6c12 {
    meta:
        id = "4S0Irf5a0tG5JGmrf4dr1g"
        fingerprint = "v1_sha256_6aa72029eeeb2edd2472bf0db80b9c0ae4033d7d977cbee75ac94414d1cdff7a"
        version = "1.0"
        date = "2023-04-03"
        modified = "2024-10-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.XWorm"
        reference_sample = "bf5ea8d5fd573abb86de0f27e64df194e7f9efbaadd5063dee8ff9c5c3baeaa2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "startsp" ascii wide fullword
        $str2 = "injRun" ascii wide fullword
        $str3 = "getinfo" ascii wide fullword
        $str4 = "Xinfo" ascii wide fullword
        $str5 = "openhide" ascii wide fullword
        $str6 = "WScript.Shell" ascii wide fullword
        $str7 = "hidefolderfile" ascii wide fullword
    condition:
        all of them
}

rule Windows_Trojan_XWorm_b7d6eaa8 {
    meta:
        id = "74xqVm8PLPyx4N91D6xuqL"
        fingerprint = "v1_sha256_6a9da68dd1475974e71043a0e5a51d70762473c385d6acef34945019c7016b02"
        version = "1.0"
        date = "2024-09-10"
        modified = "2024-10-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.XWorm"
        reference_sample = "6fc4ff3f025545f7e092408b035066c1138253b972a2e9ef178e871d36f03acd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "XWorm V" wide
        $str2 = "XLogger" ascii fullword
        $str3 = "<Xwormmm>" wide fullword
        $str4 = "ActivatePong" ascii fullword
        $str5 = "ReportWindow" ascii fullword
        $str6 = "ConnectServer" ascii fullword
    condition:
        4 of them
}

rule Windows_Trojan_XWorm_7078e1c8 {
    meta:
        id = "6VmUWRp4sNPNTUwfMbecy6"
        fingerprint = "v1_sha256_4c69648e4a68c8c46cf435f4dcac79176a023d8cd7209f9fa6a6b244797c66f3"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.XWorm"
        reference_sample = "034c8a18c15521069af36595357d9c8413a33544af8d3ea5f0ac7d471841e0ec"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 72 5D 01 00 70 17 6F 29 00 00 0A 7E 21 00 00 04 28 2A 00 00 0A 09 6F 2B 00 00 0A 09 28 2C 00 00 0A 2C 0F 09 73 2D 00 00 0A 13 04 11 04 6F 2E 00 00 0A 20 E8 03 00 00 28 1F 00 00 0A }
    condition:
        all of them
}

