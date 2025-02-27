rule Windows_Trojan_MagicRat_c14c4d85 {
    meta:
        id = "43mWZ6EnhRCUPALOFCkawr"
        fingerprint = "v1_sha256_f6b22d0b50c266d0628d1132a0aabef2816b9e68cb74af92b83b7c6fc6433326"
        version = "1.0"
        date = "2024-12-27"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.MagicRat"
        reference_sample = "9dc04153455d054d7e04d46bcd8c13dd1ca16ab2995e518ba9bf33b43008d592"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str_0 = "MagicSystem" fullword
        $str_1 = "MagicMon" fullword
        $str_2 = "company/oracle" fullword
        $str_3 = "company/microsoft" fullword
        $str_4 = "images/body/" fullword
        $str_5 = "&filename=" fullword
        $str_6 = "os/mac" fullword
        $str_7 = "form-data; name=\"session\";" fullword
    condition:
        5 of them
}

