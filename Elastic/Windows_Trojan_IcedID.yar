rule Windows_Trojan_IcedID_1cd868a6 {
    meta:
        id = "6ALOao9P1g5DHJXuvMkP8j"
        fingerprint = "v1_sha256_4765b2b1d463f09d7e21367c2832b3ad668aa67d8078798a14295b6e6c846c1c"
        version = "1.0"
        date = "2021-02-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "68dce9f214e7691db77a2f03af16a669a3cb655699f31a6c1f5aaede041468ff"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 24 2C B9 09 00 00 00 2A C2 2C 07 88 44 24 0F 0F B6 C3 6B C0 43 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_237e9fb6 {
    meta:
        id = "1e5JQIYfmrhTshYO2sWm6"
        fingerprint = "v1_sha256_31479eae077b2d78cb1770eef3b37bec941f35c9ceb329e01dd65a32e785fa74"
        version = "1.0"
        date = "2021-02-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 60 8B 55 D4 3B D0 7E 45 83 F8 08 0F 4C 45 EC 3B D0 8D 3C 00 0F }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_f1ce2f0a {
    meta:
        id = "1YYQINMPmhV58IFryWnvre"
        fingerprint = "v1_sha256_a1f1824a7208201616dde40bea514dfc2cdf908bd8ed24b9f96c2bcad2c8107f"
        version = "1.0"
        date = "2021-02-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 8B C8 8B C6 F7 E2 03 CA 8B 54 24 14 2B D0 8B 44 24 14 89 54 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_08530e24 {
    meta:
        id = "1XhKbL12yeML21Pf1YSVNi"
        fingerprint = "v1_sha256_a63511edde9d873e184ddb4720b4752b0e7df4bdb2114b05c16f2ca0594eb6b8"
        version = "1.0"
        date = "2021-03-21"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "31db92c7920e82e49a968220480e9f130dea9b386083b78a79985b554ecdc6e4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "c:\\ProgramData\\" ascii fullword
        $a2 = "loader_dll_64.dll" ascii fullword
        $a3 = "aws.amazon.com" wide fullword
        $a4 = "Cookie: __gads=" wide fullword
        $b1 = "LookupAccountNameW" ascii fullword
        $b2 = "GetUserNameA" ascii fullword
        $b3 = "; _gat=" wide fullword
        $b4 = "; _ga=" wide fullword
        $b5 = "; _u=" wide fullword
        $b6 = "; __io=" wide fullword
        $b7 = "; _gid=" wide fullword
        $b8 = "%s%u" wide fullword
        $b9 = "i\\|9*" ascii fullword
        $b10 = "WinHttpSetStatusCallback" ascii fullword
    condition:
        all of ($a*) and 5 of ($b*)
}

rule Windows_Trojan_IcedID_11d24d35 {
    meta:
        id = "1AAlx6yV1mLXrObGxKmG7t"
        fingerprint = "v1_sha256_4a5d0f37e3e80e370ae79fd45256dbd274ed8f8bcd021e8d6f95a0bc0bc5321f"
        version = "1.0"
        date = "2022-02-16"
        modified = "2022-04-06"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b8d794f6449669ff2d11bc635490d9efdd1f4e92fcb3be5cdb4b40e4470c0982"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "C:\\Users\\user\\source\\repos\\anubis\\bin\\RELEASE\\loader_dll_64.pdb" ascii fullword
        $a2 = "loader_dll_64.dll" ascii fullword
    condition:
        1 of ($a*)
}

rule Windows_Trojan_IcedID_0b62e783 {
    meta:
        id = "5HmAyStZzixpQ4cXeM3NBB"
        fingerprint = "v1_sha256_aca126529dfa8047ed7dfdc60d970759ab5307448d7d764f88e402cd8d2a016f"
        version = "1.0"
        date = "2022-04-06"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 89 44 95 E0 83 E0 07 8A C8 42 8B 44 85 E0 D3 C8 FF C0 42 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_91562d18 {
    meta:
        id = "64AKbIIgionXWnHM552lGa"
        fingerprint = "v1_sha256_81c87d0d6726bc2dde42fe93c77af53cdd29bb6437fe3d47d1b4550140722c88"
        version = "1.0"
        date = "2022-04-06"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 44 8B 4C 19 2C 4C 03 D6 74 1C 4D 85 C0 74 17 4D 85 C9 74 12 41 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_2086aecb {
    meta:
        id = "6cRaunAoSwMllMC6QVif8K"
        fingerprint = "v1_sha256_561bf7eacfbbf1b4e0c111347f0d6ff4325bdbce8db73bee1ba836b610569c0d"
        version = "1.0"
        date = "2022-04-06"
        modified = "2022-03-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 4C 8D 05 [4] 42 8A 44 01 ?? 42 32 04 01 88 44 0D ?? 48 FF C1 48 83 F9 20 72 ?? }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_48029e37 {
    meta:
        id = "3KP2FYfmn3mPSHYGbMAFHb"
        fingerprint = "v1_sha256_1fe337d7a0607938aaf57cf25c1373aadf315b7a8cec133d6d30a38bd58e1027"
        version = "1.0"
        date = "2022-04-06"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 C1 E3 10 0F 31 48 C1 E2 ?? 48 0B C2 0F B7 C8 48 0B D9 8B CB 83 E1 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_56459277 {
    meta:
        id = "6llkt8RMpiTgaDT3nK3Qnx"
        fingerprint = "v1_sha256_a18557217c69a3bb8c3da7725d2e0ed849741f8e36341a4ea80eea09d47a5b45"
        version = "1.0"
        date = "2022-08-21"
        modified = "2023-03-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "IcedID Gzip Variant Core"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "21b1a635db2723266af4b46539f67253171399830102167c607c6dbf83d6d41c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "cookie.tar" ascii fullword
        $str2 = "passff.tar" ascii fullword
        $str3 = "\\sqlite64.dll" ascii fullword
        $str4 = "Cookie: session=" ascii fullword
        $str5 = "{0ccac395-7d1d-4641-913a-7558812ddea2}" ascii fullword
        $str6 = "mail_vault" wide fullword
        $seq_decrypt_payload = { 42 0F B6 04 32 48 FF C2 03 C8 C1 C1 ?? 48 3B D7 72 ?? 44 33 F9 45 33 C9 44 89 3C 3B 48 85 FF 74 ?? 41 0F B6 D1 44 8D 42 01 83 E2 03 41 83 E0 03 }
        $seq_compute_hash = { 0F B6 4C 14 ?? 48 FF C2 8B C1 83 E1 ?? 48 C1 E8 ?? 41 0F B7 04 41 66 89 03 48 8D 5B ?? 41 0F B7 0C 49 66 89 4B ?? 48 83 FA ?? 72 ?? 66 44 89 03 B8 }
        $seq_format_string = { C1 E8 ?? 44 0B D8 41 0F B6 D0 8B C1 C1 E2 ?? C1 E1 ?? 25 [4] 0B C1 41 C1 E8 ?? 41 0F B6 CA 41 0B D0 44 8B 44 24 ?? C1 E0 ?? C1 E1 ?? 41 C1 EB ?? 44 0B D8 41 C1 EA ?? 0F B7 44 24 ?? 41 0B CA }
        $seq_custom_ror = { 41 8A C0 41 8A D0 02 C0 0F B6 C8 8A C1 44 8B C1 34 ?? 84 D2 0F B6 C8 44 0F 48 C1 49 83 EB }
        $seq_string_decrypt = { 0F B7 44 24 ?? 0F B7 4C 24 ?? 3B C1 7D ?? 8B 4C 24 ?? E8 [4] 89 44 24 ?? 0F B7 44 24 ?? 48 8B 4C 24 ?? 0F B6 04 01 0F B6 4C 24 ?? 33 C1 0F B7 4C 24 ?? 48 8B 54 24 ?? 88 04 0A EB }
    condition:
        5 of ($str*) or 2 of ($seq_*)
}

rule Windows_Trojan_IcedID_7c1619e3 {
    meta:
        id = "2iB4x8cLGSqRepZ656tO9O"
        fingerprint = "v1_sha256_24ddaf474dabc5e91cce08734a035feced9048a3faac4ff236bc97e6caabd642"
        version = "1.0"
        date = "2022-12-20"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "IcedID Injector Variant Loader "
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "4f6de748628b8b06eeef3a5fabfe486bfd7aaa92f50dc5a8a8c70ec038cd33b1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 84 C0 75 ?? 8B 74 24 ?? 81 F1 [4] 39 16 76 }
        $a2 = { D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 }
        $a3 = { 8B 4E ?? FF 74 0B ?? 8B 44 0B ?? 03 C1 50 8B 44 0B ?? 03 46 ?? 50 E8 [4] 8B 46 ?? 8D 5B ?? 83 C4 0C 47 3B 78 }
    condition:
        all of them
}

rule Windows_Trojan_IcedID_d8b23cd6 {
    meta:
        id = "6DVsmNaTgWK2B1s7xt6Q73"
        fingerprint = "v1_sha256_47e427a4f088de523115f438cad9fc26233158b0518d87703c282df351110762"
        version = "1.0"
        date = "2023-01-03"
        modified = "2023-01-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "IcedID VNC server"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "bd4da2f84c29437bc7efe9599a3a41f574105d449ac0d9b270faaca8795153ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "User idle %u sec / Locked: %s / ScreenSaver: %s" wide
        $a2 = "No VNC HOOK" wide
        $a3 = "Webcam %u" wide
        $a4 = "rundll32.exe shell32.dll,#61"
        $a5 = "LAP WND"
        $a6 = "FG WND"
        $a7 = "CAP WND"
        $a8 = "HDESK Tmp" wide
        $a9 = "HDESK Bot" wide
        $a10 = "HDESK bot" wide
        $a11 = "CURSOR: %u, %u"
        $b1 = { 83 7C 24 ?? 00 75 ?? 83 7C 24 ?? 00 75 ?? [1] 8B 0D [4] 8B 44 24 }
    condition:
        6 of them
}

rule Windows_Trojan_IcedID_a2ca5f80 {
    meta:
        id = "3QBXy0lUv6we6Vdg7WQbym"
        fingerprint = "v1_sha256_e36266cd66b9542f2eb9d38f9a01f7b480f2bcdbe61fe20944dca33e22bd3281"
        version = "1.0"
        date = "2023-01-16"
        modified = "2023-04-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "IcedID Injector Variant Core"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.Icedid"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "EMPTY"
        $a2 = "CLEAR"
        $a3 = { 66 C7 06 6D 3D 83 C6 02 0F B6 05 [4] 50 68 34 73 00 10 56 FF D7 03 F0 66 C7 06 26 6A C6 46 ?? 3D 83 C6 03 }
        $a4 = { 8B 46 ?? 6A 00 FF 76 ?? F7 D8 FF 76 ?? 1B C0 FF 76 ?? 50 FF 76 ?? 53 FF 15 }
        $a5 = { 8D 44 24 ?? 89 7C 24 ?? 89 44 24 ?? 33 F6 B8 BB 01 00 00 46 55 66 89 44 24 ?? 89 74 24 ?? E8 [4] 89 44 24 ?? 85 C0 74 ?? 8B AC 24 }
        $a6 = { 8A 01 88 45 ?? 45 41 83 EE 01 75 ?? 8B B4 24 [4] 8B 7E }
        $a7 = { 53 E8 [4] 8B D8 30 1C 2F 45 59 3B EE 72 }
        $a8 = { 8B 1D [4] 33 D9 6A 00 53 52 E8 [4] 83 C4 0C 89 44 24 ?? 85 C0 0F 84 }
        $a9 = { C1 C9 0D 0F BE C0 03 C8 46 8A 06 }
    condition:
        4 of them
}

rule Windows_Trojan_IcedID_b8c59889 {
    meta:
        id = "5LzVfnOtAP6F3oG7RZtAAQ"
        fingerprint = "v1_sha256_08c6c604d1791c35a8494e5ec8a96e8c5dd2ca3d6c57971da20057ce8960fa1d"
        version = "1.0"
        date = "2023-05-05"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "IcedID fork init loader"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "a63d08cd53053bfda17b8707ab3a94cf3d6021097335dc40d5d211fb9faed045"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" wide fullword
        $a2 = "\\1.bin" wide fullword
        $a3 = "c:\\ProgramData" wide fullword
        $a4 = "Loader.dll" ascii fullword
        $seq_crypto = { 83 E1 03 83 E0 03 48 8D 14 8A 41 8B 0C 80 4D 8D 04 80 41 0F B6 00 83 E1 07 02 02 41 32 04 29 41 88 04 19 49 FF C1 8B 02 }
    condition:
        4 of ($a*) or 1 of ($seq*)
}

rule Windows_Trojan_IcedID_81eff9a3 {
    meta:
        id = "5iQupwCsmTgqKtqr4tXs5U"
        fingerprint = "v1_sha256_923dd8166cce0ec32b3b8b20cad192b3c15b7ce7c17fd44ddda739ad205a6c06"
        version = "1.0"
        date = "2023-05-05"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "IcedID fork core bot loader"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
        threat_name = "Windows.Trojan.IcedID"
        reference_sample = "96dacdf50d1db495c8395d7cf454aa3a824801cf366ac368fe496f89b5f98fe7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = "E:\\source\\anubis\\int-bot\\x64\\Release\\int-bot.pdb" ascii fullword
    condition:
        all of them
}

