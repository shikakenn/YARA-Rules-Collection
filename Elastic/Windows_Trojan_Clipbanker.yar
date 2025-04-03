rule Windows_Trojan_Clipbanker_7efaef9f {
    meta:
        id = "7aB5FBpPL7GIsBOdZsbG0S"
        fingerprint = "v1_sha256_fa547d7c1623b332ef306672dd2293b44016d9974c1a3ec4b15e5ae0483ff879"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "02b06acb113c31f5a2ac9c99f9614e0fab0f78afc5ae872e46bae139c2c9b1f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "C:\\Users\\youar\\Desktop\\Allcome\\Source code\\Build\\Release\\Build.pdb" ascii fullword
        $b1 = "https://steamcommunity.com/tradeoffer" ascii fullword
        $b2 = "/Create /tn NvTmRep_CrashReport3_{B2FE1952-0186} /sc MINUTE /tr %s" ascii fullword
        $b3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" ascii fullword
        $b4 = "ProcessHacker.exe" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Clipbanker_b60a50b8 {
    meta:
        id = "4p6MQUSOMYaCaw9dArW8fy"
        fingerprint = "v1_sha256_fe585ab7efbc3b500ea23d1c164bc79ded658001e53fc71721e435ed7579182a"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "02b06acb113c31f5a2ac9c99f9614e0fab0f78afc5ae872e46bae139c2c9b1f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 40 66 0F F8 C1 0F 11 40 A0 0F 10 84 15 08 FF FF FF 83 C2 40 }
    condition:
        all of them
}

rule Windows_Trojan_Clipbanker_f9f9e79d {
    meta:
        id = "3M52jFkJtFhhoij9ZEAdaB"
        fingerprint = "v1_sha256_a71d75719133e8b84956ec002cb31f82386ef711fa2af79d204d176492cd354b"
        version = "1.0"
        date = "2022-04-23"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "0407e8f54490b2a24e1834d99ec0452f217499f1e5a64de3d28439d71d16d43c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 7E 7E 0F B7 04 77 83 F8 41 74 69 83 F8 42 74 64 83 F8 43 74 5F 83 }
    condition:
        all of them
}

rule Windows_Trojan_Clipbanker_787b130b {
    meta:
        id = "5xCbYeB7XbSiSFwDmuocyC"
        fingerprint = "v1_sha256_88783bde7014853f6556c6e7ee2dfd5cd5fcbfb4523ed158b4287e2bfba409f1"
        version = "1.0"
        date = "2022-04-24"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Clipbanker"
        reference_sample = "0407e8f54490b2a24e1834d99ec0452f217499f1e5a64de3d28439d71d16d43c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $mutex_setup = { 55 8B EC 83 EC ?? 53 56 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 6A ?? FF 15 ?? ?? ?? ?? }
        $new_line_check = { 0F B7 C2 89 45 ?? 0F B7 C2 83 F8 0A 74 ?? BA 0D 0A 00 00 66 3B C2 74 ?? 83 F8 0D 74 ?? 83 F8 20 74 ?? 83 F8 09 74 ?? }
        $regex1 = { 0F B7 C2 89 45 ?? 0F B7 C2 83 F8 0A 74 ?? BA 0D 0A 00 00 66 3B C2 74 ?? 83 F8 0D 74 ?? 83 F8 20 74 ?? 83 F8 09 74 ?? }
        $regex2 = { 6A 34 59 66 39 0E 75 ?? 0F B7 46 ?? 6A 30 5A 83 F8 41 74 ?? 83 F8 42 74 ?? 66 3B C2 74 ?? 83 F8 31 74 ?? 83 F8 32 74 ?? 83 F8 33 74 ?? 66 3B C1 74 ?? 83 F8 35 74 ?? 83 F8 36 74 ?? 83 F8 37 74 ?? 83 F8 38 74 ?? 83 F8 39 75 ?? }
        $regex3 = { 56 8B F1 56 FF 15 ?? ?? ?? ?? 83 F8 5F 0F 85 ?? ?? ?? ?? 6A 38 59 66 39 0E 75 ?? 0F B7 46 ?? 6A 30 5A 83 F8 41 74 ?? 83 F8 42 74 ?? 66 3B C2 74 ?? 83 F8 31 74 ?? 83 F8 32 74 ?? 83 F8 33 74 ?? 83 F8 34 74 ?? 83 F8 35 74 ?? 83 F8 36 74 ?? 83 F8 37 74 ?? 66 3B C1 74 ?? 83 F8 39 75 ?? }
    condition:
        any of them
}

