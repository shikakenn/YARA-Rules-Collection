rule Windows_Trojan_BruteRatel_1916686d {
    meta:
        id = "6LWGym8KtJsWUuZmqgZdMo"
        fingerprint = "v1_sha256_e0e7b8ba2865fc76845b21aa3e075ceab98888635a60bd722c0c81e0f4fcf58c"
        version = "1.0"
        date = "2022-06-23"
        modified = "2022-12-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[+] Spoofed PPID => %lu" wide fullword
        $a2 = "[-] Child process not set" wide fullword
        $a3 = "[+] Crisis Monitor: Already Running" wide fullword
        $a4 = "[+] Screenshot downloaded: %S" wide fullword
        $a5 = "s[-] Duplicate listener: %S" wide fullword
        $a6 = "%02d%02d%d_%02d%02d%2d%02d.png" wide fullword
        $a7 = "[+] Added Socks Profile" wide fullword
        $a8 = "[+] Dump Size: %d Mb" wide fullword
        $a9 = "[+] Enumerating PID: %lu [%ls]" wide fullword
        $a10 = "[+] Dump Size: %d Mb" wide fullword
        $a11 = "[+] SAM key: " wide fullword
        $a12 = "[+] Token removed: '%ls'" wide fullword
        $a13 = "[Tasks] %02d => 0x%02X 0x%02X" wide fullword
        $b1 = { 48 83 EC ?? 48 8D 35 ?? ?? ?? ?? 4C 63 E2 31 D2 48 8D 7C 24 ?? 48 89 CB 4D 89 E0 4C 89 E5 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 31 F6 BF ?? ?? ?? ?? 39 F5 7E ?? E8 ?? ?? ?? ?? 99 F7 FF 48 63 D2 8A 44 14 ?? 88 04 33 48 FF C6 EB ?? }
    condition:
        4 of ($a*) or 1 of ($b*)
}

rule Windows_Trojan_BruteRatel_9b267f96 {
    meta:
        id = "3qSW2TngCz7kxLmWX42dgU"
        fingerprint = "v1_sha256_fbaaf4bf2462119b39a5df90b91fb831be3e602b926cd893374a5dddf48f029d"
        version = "1.0"
        date = "2022-06-23"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "calAllocPH" ascii fullword
        $a2 = "lizeCritPH" ascii fullword
        $a3 = "BadgerPH" ascii fullword
        $a4 = "VirtualPPH" ascii fullword
        $a5 = "TerminatPH" ascii fullword
        $a6 = "ickCountPH" ascii fullword
        $a7 = "SeDebugPH" ascii fullword
        $b1 = { 50 48 B8 E2 6A 15 64 56 22 0D 7E 50 48 B8 18 2C 05 7F BB 78 D7 27 50 48 B8 C9 EC BC 3D 84 54 9A 62 50 48 B8 A1 E1 3C 4E AF 2B F6 B1 50 48 B8 2E E6 7B A0 94 CA 9D F0 50 48 B8 61 52 80 AA 1A B6 4B 0E 50 48 B8 B2 13 11 5A 28 81 ED 60 50 48 B8 20 DE A9 34 89 08 C8 32 50 48 B8 9B DC C1 FF 79 CE 5B F5 50 48 B8 FD 57 3F 4C C7 D3 7A 21 50 48 B8 70 B8 63 0F AB 19 BF 1C 50 48 B8 48 F2 1B 72 1E 2A C6 8A 50 48 B8 E3 FA 38 E9 1D 76 E0 6F 50 48 B8 97 AD 75 }
    condition:
        3 of ($a*) or 1 of ($b*)
}

rule Windows_Trojan_BruteRatel_684a39f2 {
    meta:
        id = "18BXdiQfgBoPBrevpn7v2"
        fingerprint = "v1_sha256_7cb74176e1dbdd248295649568d29c9d88841fcd0c16479b6b7efc71c4a1d706"
        version = "1.0"
        date = "2023-01-24"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "5f4782a34368bb661f413f33e2d1fb9f237b7f9637f2c0c21dc752316b02350c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $seq1 = { 39 DA 0F 82 61 02 00 00 45 8D 48 14 44 39 CA 0F 82 54 02 00 00 41 8D 40 07 46 0F B6 0C 09 44 0F B6 1C 01 42 0F B6 04 11 41 C1 E3 08 41 09 C3 }
        $seq2 = { 45 8A 44 13 F0 44 32 04 01 48 FF C0 45 88 04 13 48 FF C2 48 83 F8 04 75 E7 49 83 C2 04 48 83 C6 04 49 81 FA B0 00 00 00 75 AA 48 83 C4 38 5B 5E C3 }
        $seq3 = { 48 83 EC 18 8A 01 88 04 24 8A 41 05 88 44 24 01 8A 41 0A 88 44 24 02 8A 41 0F 88 44 24 03 8A 41 04 88 44 24 04 8A 41 09 88 44 24 05 8A 41 0E 88 44 24 06 8A 41 03 88 44 24 07 }
        $seq4 = { 42 8A 0C 22 8D 42 ?? 80 F9 ?? 75 ?? 48 98 4C 89 E9 48 29 C1 42 8A 14 20 80 FA ?? 74 ?? 88 14 01 48 FF C0 EB ?? }
        $cfg1 = { 22 00 2C 00 22 00 61 00 72 00 63 00 68 00 22 00 3A 00 22 00 78 00 36 00 34 00 22 00 2C 00 22 00 62 00 6C 00 64 00 22 00 3A 00 22 00 }
        $cfg2 = { 22 00 2C 00 22 00 77 00 76 00 65 00 72 00 22 00 3A 00 22 00 }
        $cfg3 = { 22 00 2C 00 22 00 70 00 69 00 64 00 22 00 3A 00 22 00 }
        $cfg4 = { 22 00 7D 00 2C 00 22 00 6D 00 74 00 64 00 74 00 22 00 3A 00 7B 00 22 00 68 00 5F 00 6E 00 61 00 6D 00 65 00 22 00 3A 00 22 00 }
    condition:
        any of ($seq*) and all of ($cfg*)
}

rule Windows_Trojan_BruteRatel_ade6c9d5 {
    meta:
        id = "2RYcLBA81Rutxykt2VIfjR"
        fingerprint = "v1_sha256_8ff8ed1e2b909606fe6aae3f43ad02898d7b3906c3d329a508f6d40490ec75a0"
        version = "1.0"
        date = "2023-01-24"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Targets API hashes used by BruteRatel"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "dc9757c9aa3aff76d86f9f23a3d20a817e48ca3d7294307cc67477177af5c0d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1_NtReadVirtualMemory = { AA A5 EF 3A }
        $c2_NtQuerySystemInformation = { D6 CA E1 E4 }
        $c3_NtCreateFile = { 9D 8F 88 03 }
        $c4_RtlSetCurrentTranscation = { 90 85 A3 99 }
        $c5_LoadLibrary = { 8E 4E 0E EC }
    condition:
        all of them
}

rule Windows_Trojan_BruteRatel_4110d879 {
    meta:
        id = "1SEo6W4toFiD0bo7AGBuNr"
        fingerprint = "v1_sha256_22c27523ddd8183c41da40f7ff908ae5bdee3b482c8a3f70aaa63a4c419e515b"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "e0fbbc548fdb9da83a72ddc1040463e37ab6b8b544bf0d2b206bfff352175afe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 04 01 75 E2 48 83 C0 01 44 0F B6 04 02 45 84 C0 75 EC 48 89 }
        $a2 = { C8 48 83 E9 20 44 0F B6 40 E0 41 80 F8 E9 74 0B 44 0F B6 49 03 41 80 }
    condition:
        all of them
}

rule Windows_Trojan_BruteRatel_5b12cbab {
    meta:
        id = "5Ou5HVvOTipt7VdcgJIjtj"
        fingerprint = "v1_sha256_b86296dafaef1dfa0a41704cafa351694abb0e453e104dfe06836ed599338f38"
        version = "1.0"
        date = "2024-02-21"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "8165798fec8294523f25aedfc6699faad0c5d75f60bc7cefcbb2fa13dbc656e3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 81 EC 00 01 00 00 31 C0 41 89 D3 48 89 E3 88 04 18 48 FF C0 48 3D 00 01 00 00 75 F2 45 31 D2 31 FF 44 89 D0 42 8A 34 13 99 41 F7 FB 48 63 D2 8A 04 11 01 F0 01 F8 0F B6 F8 0F B6 C0 8A 14 04 }
    condition:
        all of them
}

rule Windows_Trojan_BruteRatel_5e383ae0 {
    meta:
        id = "1Xkki55naBsz5g1p9UDJjL"
        fingerprint = "v1_sha256_5d87ada1c609e23742c389f8153a9266c4db95be4a5e10b50979aebc993a45e0"
        version = "1.0"
        date = "2024-03-27"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "0b506ef32f58ee2b1e5701ca8e13c67584739ab1d00ee4a0c2f532c09a15836f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "_imp_BadgerWcslen"
        $a2 = "_imp_BadgerStrcmp"
        $a3 = "_imp_BadgerDispatch"
        $a4 = "_imp_BadgerStrlen"
        $a5 = "_imp_BadgerMemset"
        $a6 = "_imp_BadgerMemcpy"
        $a7 = "_imp_BadgerWcscmp"
        $a8 = "_imp_BadgerAlloc"
        $a9 = "_imp_BadgerFree"
        $a10 = "_imp_BadgerSetdebug"
        $a11 = "_imp_BadgerGetBufferSize"
        $b1 = "__imp_Kernel32$"
        $b2 = "__imp_Ntdll$Nt"
        $b3 = "__imp_Advapi32$"
        $b4 = "__imp_NETAPI32$"
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_BruteRatel_644ac114 {
    meta:
        id = "5yHUKdsx9BRIm6oEGU2T5P"
        fingerprint = "v1_sha256_06ffea16a0348f2276f379db150b5f9d2dbdffbcb2eee83c55c27c837ecb1e69"
        version = "1.0"
        date = "2024-04-17"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BruteRatel"
        reference_sample = "ace6a99d95ef859d4ab74db6900753e754273a12a34721f1aa8f1a9df3d8ec35"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 80 39 0F 75 ?? 80 79 01 05 75 ?? 80 79 02 C3 75 ?? 48 89 C8 C3 }
        $b = { 80 79 01 8B 75 ?? 80 79 02 D1 75 ?? 41 80 F9 B8 75 ?? 80 79 06 00 75 ?? 0F B6 41 05 C1 E0 08 41 89 C0 0F B6 41 04 }
    condition:
        all of them
}

