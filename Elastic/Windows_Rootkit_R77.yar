rule Windows_Rootkit_R77_5bab748b {
    meta:
        id = "126ZKsMbhwKmPw2B6aPMBJ"
        fingerprint = "v1_sha256_ebf851ef41fde8e3118acc742cd2b38651f662a00f11dd6f7c65cf56019c43d5"
        version = "1.0"
        date = "2022-03-04"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
        threat_name = "Windows.Rootkit.R77"
        reference_sample = "cfc76dddc74996bfbca6d9076d2f6627912ea196fdbdfb829819656d4d316c0c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 01 04 10 41 8B 4A 04 49 FF C1 48 8D 41 F8 48 D1 E8 4C 3B C8 }
    condition:
        all of them
}

rule Windows_Rootkit_R77_eb366abc {
    meta:
        id = "2m086BGGiIW6y841n8qJoP"
        fingerprint = "v1_sha256_3d6f1c60bf749c53f4a4fcfd6490d309e4450d5f7e64de4665c3d80af1bce44f"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
        threat_name = "Windows.Rootkit.R77"
        reference_sample = "21e7f69986987fc75bce67c4deda42bd7605365bac83cf2cecb25061b2d86d4f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 8C 20 88 00 00 00 42 8B 44 21 10 42 8B 4C 21 1C 48 2B D0 49 }
        $a2 = { 53 00 4F 00 46 00 54 00 57 00 41 00 52 00 45 00 5C 00 24 00 37 00 37 00 63 00 6F 00 6E 00 66 00 69 00 67 00 }
    condition:
        all of them
}

rule Windows_Rootkit_R77_99050e7d {
    meta:
        id = "61yWgSvgvch4Mbxii0hZyr"
        fingerprint = "v1_sha256_0fedf4698cc652076090b1fe256d05d2c0bc3ad2ab7ed5faa270c5c7fe0efca1"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
        threat_name = "Windows.Rootkit.R77"
        reference_sample = "3dc94c88caa3169e096715eb6c2e6de1b011120117c0a51d12f572b4ba999ea6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 24 00 37 00 37 00 63 00 68 00 69 00 6C 00 64 00 70 00 72 00 6F 00 63 00 36 00 34 00 }
        $a2 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 24 00 37 00 37 00 63 00 68 00 69 00 6C 00 64 00 70 00 72 00 6F 00 63 00 33 00 32 00 }
    condition:
        all of them
}

rule Windows_Rootkit_R77_be403e3c {
    meta:
        id = "20B2iGz69mSMAV9yfRHr7c"
        fingerprint = "v1_sha256_efbf924c7a299f2543c639b6262007eb3bdbf6ff5e33dab7d6102814b9477811"
        version = "1.0"
        date = "2023-05-18"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
        threat_name = "Windows.Rootkit.R77"
        reference_sample = "91c6e2621121a6871af091c52fafe41220ae12d6e47e52fd13a7b9edd8e31796"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 33 C9 48 89 8C 24 C0 00 00 00 4C 8B CB 48 89 8C 24 B8 00 00 00 45 33 C0 48 89 8C 24 B0 00 00 00 48 89 8C 24 A8 00 00 00 89 8C 24 A0 00 00 00 }
    condition:
        $a
}

rule Windows_Rootkit_R77_ee853c9f {
    meta:
        id = "365OVA7NAsO0xaIxjWNkn0"
        fingerprint = "v1_sha256_94f080f310ecace76da32ba2b4edcc80dedfb339113823708167c1d842db8cf3"
        version = "1.0"
        date = "2023-05-18"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
        threat_name = "Windows.Rootkit.R77"
        reference_sample = "916c805b0d512dd7bbd88f46632d66d9613de61691b4bd368e4b7cb1f0ac7f60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $r77_str0 = "$77stager" wide fullword
        $r77_str1 = "$77svc32" wide fullword
        $r77_str2 = "$77svc64" wide fullword
        $r77_str3 = "\\\\.\\pipe\\$77childproc64" wide fullword
        $r77_str4 = "SOFTWARE\\$77config"
        $obfuscate_ps = { 0F B7 04 4B 33 D2 C7 45 FC 34 00 00 00 F7 75 FC 66 8B 44 55 90 66 89 04 4B 41 3B CE }
        $amsi_patch_ps = "[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0,7,0x80,0xc3)" wide fullword
    condition:
        ($obfuscate_ps and $amsi_patch_ps) or (all of ($r77_str*))
}

rule Windows_Rootkit_R77_d0367e28 {
    meta:
        id = "49c6w0ZUJnjr1m27AcGxs7"
        fingerprint = "v1_sha256_588b18c54c344ca267b86143df20c7dcaab081e0ef6acae0bd0dae61593eb521"
        version = "1.0"
        date = "2023-05-18"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
        threat_name = "Windows.Rootkit.R77"
        reference_sample = "96849108e13172d14591169f8fdcbf8a8aa6be05b7b6ef396d65529eacc02d89"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str0 = "service_names" wide fullword
        $str1 = "process_names" wide fullword
        $str2 = "tcp_local" wide fullword
        $str3 = "tcp_remote" wide fullword
        $str4 = "startup" wide fullword
        $str5 = "ReflectiveDllMain" ascii fullword
        $str6 = ".detourd" ascii fullword
        $binary0 = { 48 8B 10 48 8B 0B E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 08 48 8B 4B 08 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 10 48 8B 4B 10 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 18 48 8B 4B 18 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 20 48 8B 4B 20 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 28 48 8B 4B 28 E8 ?? ?? ?? ?? 85 C0 }
        $binary1 = { 8B 56 04 8B 4F 04 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 08 8B 4F 08 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 0C 8B 4F 0C E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 10 8B 4F 10 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 14 8B 4F 14 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 18 8B 4F 18 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 1C 8B 4F 1C }
    condition:
        (all of ($str*)) or $binary0 or $binary1
}

