rule Windows_Ransomware_Maze_61254061 : beta {
    meta:
        id = "5Lg1MfU2Mm0vtDz2Ovimqt"
        fingerprint = "v1_sha256_b8537add953cdd7bc6adbff97f7f5a94de028709f0bd71102ee96d26d55f4f20"
        version = "1.0"
        date = "2020-04-18"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies MAZE ransomware"
        category = "INFO"
        reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
        threat_name = "Windows.Ransomware.Maze"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1 = { FC 8B 55 08 8B 44 8A 10 C1 E0 09 8B 4D FC 8B 55 08 8B 4C 8A 10 C1 }
        $c2 = { 72 F0 0C 66 0F 72 D4 14 66 0F EB C4 66 0F 70 E0 39 66 0F FE E6 66 0F 70 }
    condition:
        1 of ($c*)
}

rule Windows_Ransomware_Maze_46f40c40 : beta {
    meta:
        id = "4m1Y172xyNYzVun3CNUUGs"
        fingerprint = "v1_sha256_99180f41aaaf1dfb0a8a40709dcc392fdbc2b2d3a4d4b4a1ab160dd5f2b4c703"
        version = "1.0"
        date = "2020-04-18"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies MAZE ransomware"
        category = "INFO"
        reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
        threat_name = "Windows.Ransomware.Maze"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b1 = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" wide fullword
        $b2 = "Maze Ransomware" wide fullword
        $b3 = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" wide fullword
    condition:
        2 of ($b*)
}

rule Windows_Ransomware_Maze_20caee5b : beta {
    meta:
        id = "1ElAfL4o64RHklwwl8Ulnp"
        fingerprint = "v1_sha256_e09c059b285d2176aeba1a1f70d39f13cef4e05dc023c7db25fb9d92bd9a67d9"
        version = "1.0"
        date = "2020-04-18"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies MAZE ransomware"
        category = "INFO"
        reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
        threat_name = "Windows.Ransomware.Maze"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Win32_ShadowCopy.id='%s'" wide fullword
        $a2 = "\"%s\" shadowcopy delete" wide fullword
        $a3 = "%spagefile.sys" wide fullword
        $a4 = "%sswapfile.sys" wide fullword
        $a5 = "Global\\%s" wide fullword
        $a6 = "DECRYPT-FILES.txt" wide fullword
        $a7 = "process call create \"cmd /c start %s\"" wide fullword
    condition:
        4 of ($a*)
}

rule Windows_Ransomware_Maze_f88f136f : beta {
    meta:
        id = "3kiXtumHO6KklSSVZlMoTM"
        fingerprint = "v1_sha256_5587f332a076650f6ad7b1e3b464ef6085d960e6dacf53607cf75c9f9ad07628"
        version = "1.0"
        date = "2020-04-18"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies MAZE ransomware"
        category = "INFO"
        reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
        threat_name = "Windows.Ransomware.Maze"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $d1 = { 00 67 00 20 00 69 00 6E 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6F 00 6E 00 73 00 20 00 69 00 6E 00 20 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2D 00 46 00 49 00 4C 00 45 00 53 00 2E }
        $d2 = { 70 C7 8B 75 6D 97 7E FC 19 2A 39 8C A4 AE AD 9C 62 05 B7 68 47 7D 02 F7 D3 0A DA 20 82 AE A8 E7 B2 26 E1 A0 5B 4E 17 09 A6 94 74 CA B6 0B 88 B0 5F 6E 11 E3 B0 EA 2F 40 D7 A2 AB 59 52 E0 F2 C2 19 24 14 95 01 7F CA }
        $d3 = { 77 B3 50 3C B1 9B 5D D4 87 F5 17 DB E1 C7 42 D8 53 24 C2 E2 6A A8 9B 1E FB E5 48 EB 10 48 44 28 64 F8 B6 A1 41 44 D0 42 FA 85 6F 17 57 09 C4 66 93 D2 21 C5 19 71 3A A1 C5 68 2E 67 B1 02 DC D1 }
    condition:
        1 of ($d*)
}

