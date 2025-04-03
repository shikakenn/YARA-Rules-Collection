rule Windows_Trojan_XtremeRAT_cd5b60be {
    meta:
        id = "5oWnUjbMYhKX076OMLCosz"
        fingerprint = "v1_sha256_a6997ae4842bd45c440925ef2a5848b57c58e2373c0971ce6b328ea297ee97b4"
        version = "1.0"
        date = "2022-03-15"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.XtremeRAT"
        reference_sample = "735f7bf255bdc5ce8e69259c8e24164e5364aeac3ee78782b7b5275c1d793da8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s01 = "SOFTWARE\\XtremeRAT" wide fullword
        $s02 = "XTREME" wide fullword
        $s03 = "STARTSERVERBUFFER" wide fullword
        $s04 = "ENDSERVERBUFFER" wide fullword
        $s05 = "ServerKeyloggerU" ascii fullword
        $s06 = "TServerKeylogger" ascii fullword
        $s07 = "XtremeKeylogger" wide fullword
        $s08 = "XTREMEBINDER" wide fullword
        $s09 = "UnitInjectServer" ascii fullword
        $s10 = "shellexecute=" wide fullword
    condition:
        7 of ($s*)
}

