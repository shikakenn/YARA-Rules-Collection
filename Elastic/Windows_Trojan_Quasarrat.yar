rule Windows_Trojan_Quasarrat_e52df647 {
    meta:
        id = "1eWMKsLVolSI6wTsZxdxRb"
        fingerprint = "v1_sha256_41f32e0c9b3b43d10baef10060e064ad860558bcdeb4281a30d30c16615ed21d"
        version = "1.0"
        date = "2021-06-27"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Quasarrat"
        reference_sample = "a58efd253a25cc764d63476931da2ddb305a0328253a810515f6735a6690de1d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "GetKeyloggerLogsResponse" ascii fullword
        $a2 = "DoDownloadAndExecute" ascii fullword
        $a3 = "http://api.ipify.org/" wide fullword
        $a4 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide fullword
        $a5 = "\" /sc ONLOGON /tr \"" wide fullword
    condition:
        4 of them
}

