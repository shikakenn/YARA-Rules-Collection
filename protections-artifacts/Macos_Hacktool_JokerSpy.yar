rule Macos_Hacktool_JokerSpy_58a6b26d {
    meta:
        id = "2En7AbPqvbLqG3ZkH0wTTM"
        fingerprint = "v1_sha256_e9e1333c7172d5a0f06093a902edefd7f128963dbaadf77e829f032ccb04ce56"
        version = "1.0"
        date = "2023-06-19"
        modified = "2023-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
        threat_name = "Macos.Hacktool.JokerSpy"
        reference_sample = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $str1 = "ScreenRecording: NO" fullword
        $str2 = "Accessibility: NO" fullword
        $str3 = "Accessibility: YES" fullword
        $str4 = "eck13XProtectCheck"
        $str5 = "Accessibility: NO" fullword
        $str6 = "kMDItemDisplayName = *TCC.db" fullword
    condition:
        5 of them
}

