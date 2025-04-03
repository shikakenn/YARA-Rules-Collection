rule Windows_Trojan_CyberGate_517aac7d {
    meta:
        id = "2dpyjgTwARVoUsfEEhNwkQ"
        fingerprint = "v1_sha256_50e061d0c358655c03b95ccbe2d05e252501c3e6afd21dd20513019cd67e6147"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CyberGate"
        reference_sample = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "IELOGIN.abc" ascii fullword
        $a2 = "xxxyyyzzz.dat" ascii fullword
        $a3 = "_x_X_PASSWORDLIST_X_x_" ascii fullword
        $a4 = "L$_RasDefaultCredentials#0" ascii fullword
        $a5 = "\\signons1.txt" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_CyberGate_9996d800 {
    meta:
        id = "43nIlQoFz7FNxyJHcjO17W"
        fingerprint = "v1_sha256_efefc171b6390c9792145973708358f62b18b8d0180feacaf5b9267563c3f7cc"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CyberGate"
        reference_sample = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 24 08 8B 44 24 08 83 C4 14 5D 5F 5E 5B C3 55 8B EC 83 C4 F0 }
    condition:
        all of them
}

rule Windows_Trojan_CyberGate_c219a2f3 {
    meta:
        id = "399qDWMJxwmivByJvK6QNP"
        fingerprint = "v1_sha256_8075892728c610c1ceacd0df54615d2a3e833d728d631a9bf81311e8c6485f6e"
        version = "1.0"
        date = "2023-05-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CyberGate"
        reference_sample = "b7204f8caf6ace6ae1aed267de0ad6b39660d0e636d8ee0ecf88135f8a58dc42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 00 00 55 8B EC 83 C4 EC 56 57 8B 45 08 8B F0 8D 7D EC A5 A5 }
        $a2 = { 49 80 39 C3 75 F5 8B C2 C3 55 8B EC 6A 00 6A 00 6A 00 53 56 57 }
    condition:
        all of them
}

