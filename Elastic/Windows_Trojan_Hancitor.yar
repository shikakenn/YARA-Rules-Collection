rule Windows_Trojan_Hancitor_6738d84a {
    meta:
        id = "5nQyR53z6hec9ShG4DOrcC"
        fingerprint = "v1_sha256_448243b6925c4e419b1fd492ac5e8d43a7baa4492ba7a5a0b44bc8e036c77ec2"
        version = "1.0"
        date = "2021-06-17"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Hancitor"
        reference_sample = "a674898f39377e538f9ec54197689c6fa15f00f51aa0b5cc75c2bafd86384a40"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d"
        $b1 = "Rundll32.exe %s, start" ascii fullword
        $b2 = "MASSLoader.dll" ascii fullword
    condition:
        $a1 or all of ($b*)
}

