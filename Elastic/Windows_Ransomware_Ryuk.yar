rule Windows_Ransomware_Ryuk_25d3c5ba : beta {
    meta:
        id = "6sIGKXgjAJvPfglaASiP8t"
        fingerprint = "v1_sha256_4d461ff9b87e3a17637cef89ff8a85ef22f69695d4664f6fe8f271a6a5f7b4bc"
        version = "1.0"
        date = "2020-04-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RYUK ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        threat_name = "Windows.Ransomware.Ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $g1 = { 41 8B C0 45 03 C7 99 F7 FE 48 63 C2 8A 4C 84 20 }
    condition:
        1 of ($g*)
}

rule Windows_Ransomware_Ryuk_878bae7e : beta {
    meta:
        id = "5zAa2EI0Gk536PPPknmTAc"
        fingerprint = "v1_sha256_94bed2220aeb41ae8069cee56cc5299b9fc56797d3b54085b8246a03d9e8bd93"
        version = "1.0"
        date = "2020-04-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RYUK ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        threat_name = "Windows.Ransomware.Ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b2 = "RyukReadMe.html" wide fullword
        $b3 = "RyukReadMe.txt" wide fullword
    condition:
        1 of ($b*)
}

rule Windows_Ransomware_Ryuk_6c726744 : beta {
    meta:
        id = "4oeiIl1j6lqOJDSgJnhEd2"
        fingerprint = "v1_sha256_ee7586d5cbef23d1863a4dfcc5da9b97397c993268881922c681022bf4f293f0"
        version = "1.0"
        date = "2020-04-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RYUK ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        threat_name = "Windows.Ransomware.Ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "172.16." ascii fullword
        $a2 = "192.168." ascii fullword
        $a3 = "DEL /F" wide fullword
        $a4 = "lsaas.exe" wide fullword
        $a5 = "delete[]" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Ransomware_Ryuk_1a4ad952 : beta {
    meta:
        id = "1Jq6M2UBcTLqsfMrDAE4GI"
        fingerprint = "v1_sha256_bb854f5760f41e2c103c99d8f128a2546926a614dff8753eaa1287ac583e213a"
        version = "1.0"
        date = "2020-04-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RYUK ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        threat_name = "Windows.Ransomware.Ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $e1 = { 8B 0A 41 8D 45 01 45 03 C1 48 8D 52 08 41 3B C9 41 0F 45 C5 44 8B E8 49 63 C0 48 3B C3 72 E1 }
    condition:
        1 of ($e*)
}

rule Windows_Ransomware_Ryuk_72b5fd9d : beta {
    meta:
        id = "4IrVsoqErfosOlvoioSjY3"
        fingerprint = "v1_sha256_b2abc8f70df5d730ce6a7d0bc125bb623f27b292e7d575914368a8bfc0fb5837"
        version = "1.0"
        date = "2020-04-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RYUK ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        threat_name = "Windows.Ransomware.Ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $d1 = { 48 2B C3 33 DB 66 89 1C 46 48 83 FF FF 0F }
    condition:
        1 of ($d*)
}

rule Windows_Ransomware_Ryuk_8ba51798 : beta {
    meta:
        id = "3jqx2ty699UzF9UGB8vzIG"
        fingerprint = "v1_sha256_0733ae6a7e38bc2a25aa76a816284482d3ee25626559ec5af554b5f5070e534a"
        version = "1.0"
        date = "2020-04-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RYUK ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        threat_name = "Windows.Ransomware.Ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1 = "/v \"svchos\" /f" wide fullword
        $c2 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii fullword
        $c3 = "lsaas.exe" wide fullword
        $c4 = "FA_Scheduler" wide fullword
        $c5 = "ocautoupds" wide fullword
        $c6 = "CNTAoSMgr" wide fullword
        $c7 = "hrmlog" wide fullword
        $c8 = "UNIQUE_ID_DO_NOT_REMOVE" wide fullword
    condition:
        3 of ($c*)
}

rule Windows_Ransomware_Ryuk_88daaf8e : beta {
    meta:
        id = "2ByVw8Vflw84BjzYoXQUv2"
        fingerprint = "v1_sha256_6fc463976c0fb9c3e4f25d854545d07800c63730826f3974298f0077d272cff0"
        version = "1.0"
        date = "2020-04-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies RYUK ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        threat_name = "Windows.Ransomware.Ryuk"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $f1 = { 48 8B CF E8 AB 25 00 00 85 C0 74 35 }
    condition:
        1 of ($f*)
}

