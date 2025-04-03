rule Windows_Trojan_RedLineStealer_17ee6a17 {
    meta:
        id = "1H8uSQJwviBuTrtiQWbmwr"
        fingerprint = "v1_sha256_0c868d0673c01e2c115d6822c34c877db77265251167f3a890a448a1de5c6a2d"
        version = "1.0"
        date = "2021-06-12"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "RedLine.Logic.SQLite" ascii fullword
        $a2 = "RedLine.Reburn.Data.Browsers.Gecko" ascii fullword
        $a3 = "RedLine.Client.Models.Gecko" ascii fullword
        $b1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide fullword
        $b2 = "get_encryptedUsername" ascii fullword
        $b3 = "https://icanhazip.com" wide fullword
        $b4 = "GetPrivate3Key" ascii fullword
        $b5 = "get_GrabTelegram" ascii fullword
        $b6 = "<GrabUserAgent>k__BackingField" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_RedLineStealer_f54632eb {
    meta:
        id = "65mjHcjdlCQv00luVAOkYe"
        fingerprint = "v1_sha256_1779919556ee5c9a78342aabafb8408e035cb39632b25c54da6bf195894901dc"
        version = "1.0"
        date = "2021-06-12"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "ttp://checkip.amazonaws.com/logins.json" wide fullword
        $a2 = "https://ipinfo.io/ip%appdata%\\" wide fullword
        $a3 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a4 = "get_ScannedWallets" ascii fullword
        $a5 = "get_ScanTelegram" ascii fullword
        $a6 = "get_ScanGeckoBrowsersPaths" ascii fullword
        $a7 = "<Processes>k__BackingField" ascii fullword
        $a8 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii fullword
        $a9 = "<ScanFTP>k__BackingField" ascii fullword
        $a10 = "DataManager.Data.Credentials" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_RedLineStealer_3d9371fd {
    meta:
        id = "21FkfpWz9ctQwe6T8Hb1hd"
        fingerprint = "v1_sha256_1c8a64ce7615f502602ab960638dd55f4deaeea3b49d894274d64d4d0b6a1d10"
        version = "1.0"
        date = "2022-02-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "0ec522dfd9307772bf8b600a8b91fd6facd0bf4090c2b386afd20e955b25206a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "get_encrypted_key" ascii fullword
        $a2 = "get_PassedPaths" ascii fullword
        $a3 = "ChromeGetLocalName" ascii fullword
        $a4 = "GetBrowsers" ascii fullword
        $a5 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a6 = "%appdata%\\" wide fullword
        $a7 = "ScanPasswords" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_63e7e006 {
    meta:
        id = "1MD4EZEX368iZibQFU1FYb"
        fingerprint = "v1_sha256_2085eaf622b52372124e9b23d19e3e4a7fdb7a4559ad9a09216c1cbae96ca5b6"
        version = "1.0"
        date = "2023-05-01"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "e062c99dc9f3fa780ea9c6249fa4ef96bbe17fd1df38dbe11c664a10a92deece"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 30 68 44 27 25 5B 3D 79 21 54 3A }
        $a2 = { 40 5E 30 33 5D 44 34 4A 5D 48 33 }
        $a3 = { 4B EF 4D FF 44 DD 41 70 44 DC 41 00 44 DC 41 03 43 D9 3E 00 44 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_f07b3cb4 {
    meta:
        id = "70fHQzazGJHzQGKPoz04N5"
        fingerprint = "v1_sha256_64536e3b340254554154ac1b33adfb4f3c72a2c6c0d1ef27827621b905d431c5"
        version = "1.0"
        date = "2023-05-03"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "5e491625475fc25c465fc7f6db98def189c15a133af7d0ac1ecbc8d887c4feb6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 3C 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 3E 6B 5F 5F 42 61 63 6B 69 6E 67 46 69 65 6C 64 }
        $a2 = { 45 42 37 45 46 31 39 37 33 43 44 43 32 39 35 42 37 42 30 38 46 45 36 44 38 32 42 39 45 43 44 41 44 31 31 30 36 41 46 32 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_4df4bcb6 {
    meta:
        id = "mc8AhpSTeq7Os452ksIpL"
        fingerprint = "v1_sha256_d9027fa9c8d9c938159a734431bb2be67fd7cca1f898c2208f7b909157524da4"
        version = "1.0"
        date = "2023-05-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "9389475bd26c1d3fd04a083557f2797d0ee89dfdd1f7de67775fcd19e61dfbb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 34 42 30 35 43 45 42 44 37 44 37 30 46 31 36 30 37 44 34 37 34 43 41 45 31 37 36 46 45 41 45 42 37 34 33 39 37 39 35 46 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_15ee6903 {
    meta:
        id = "2VxuYEDBNSv1K933YBWCqw"
        fingerprint = "v1_sha256_22c8a1f4b5b94261cfabdbcc00e45b9437a0132d4e9d4543b734d4f303336696"
        version = "1.0"
        date = "2023-05-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "46b506cafb2460ca2969f69bcb0ee0af63b6d65e6b2a6249ef7faa21bde1a6bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 53 65 65 6E 42 65 66 6F 72 65 33 }
        $a2 = { 73 65 74 5F 53 63 61 6E 47 65 63 6B 6F 42 72 6F 77 73 65 72 73 50 61 74 68 73 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_6dfafd7b {
    meta:
        id = "1AEBVpnI3GyVtJ3WXC4GN"
        fingerprint = "v1_sha256_888bc2fdfae8673cd6bce56fc9894b3cab6d7e3c384d854d6bc8aef47fdecf1c"
        version = "1.0"
        date = "2024-01-05"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "809e303ba26b894f006b8f2d3983ff697aef13b67c36957d98c56aae9afd8852"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 33 38 46 34 33 31 41 35 34 39 34 31 31 41 45 42 33 32 38 31 30 30 36 38 41 34 43 38 33 32 35 30 42 32 44 33 31 45 31 35 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_983cd7a7 {
    meta:
        id = "2cwCjYLYCtksSI6eTgCYYf"
        fingerprint = "v1_sha256_2104bad5ec42bc72ec611607a53086a85359bdb4bf084d7377e9a8e234b0e928"
        version = "1.0"
        date = "2024-03-27"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "7aa20c57b8815dd63c8ae951e1819c75b5d2deec5aae0597feec878272772f35"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $decrypt_config_bytes = { 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 [0-6] 2A }
        $str1 = "net.tcp://" wide
        $str2 = "\\Discord\\Local Storage\\leveldb" wide
    condition:
        all of them
}

