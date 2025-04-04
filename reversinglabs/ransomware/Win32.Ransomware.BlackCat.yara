rule Win32_Ransomware_BlackCat : tc_detection malicious
{
    meta:
        id = "70s6d9roCZDEELiH8bRLsB"
        fingerprint = "v1_sha256_24932baa625aedd14b5776ba3209c9ee330e84538c5267eeb5e09e352f655835"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects BlackCat ransomware."
        category = "MALWARE"
        malware = "BLACKCAT"
        mitre_att = "S1068"
        tc_detection_type = "Ransomware"
        tc_detection_name = "BlackCat"
        tc_detection_factor = 5

    strings:

        $remote_connection_p1 = {
            8B 44 24 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? A1 ??
            ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24
            ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ??
            ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 83 F8 ?? A1 ?? ?? ?? ?? 0F 45 C1 8B 0D ?? ??
            ?? ?? 0F 45 CA 8D 54 24 ?? 89 94 24 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7
            84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ??
            ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84
            24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ??
            ?? ?? ?? 56 51 FF 50 ?? 83 C4 ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 56 68 ?? ?? ?? ??
            FF 74 24 ?? E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? E8 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ??
            ?? ?? 6A ?? 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 ?? E8 ?? ?? ?? ?? 83 F8 ?? 75
            ?? E8 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 56 68 ?? ?? ?? ?? 68 ?? ??
            ?? ?? FF 74 24 ?? E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? E8 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 85
        }

        $remote_connection_p2 = {
            C0 89 44 24 ?? 0F 88 ?? ?? ?? ?? 8B 8B ?? ?? ?? ?? 74 ?? A1 ?? ?? ?? ?? 89 CB 85 C0
            75 ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 74 24 ?? 6A ?? 50 E8
            ?? ?? ?? ?? 85 C0 89 D9 75 ?? E9 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8B 5C 24 ?? 89 44 24 ??
            53 51 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 44 24 ?? 89 F1 8D 54 24 ?? 89 44 24 ?? 89 5C 24
            ?? 89 5C 24 ?? C6 44 24 ?? ?? E8 ?? ?? ?? ?? 83 BC 24 ?? ?? ?? ?? ?? 0F 84 ?? ?? ??
            ?? 8B 84 24 ?? ?? ?? ?? 8B 9C 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 44 24 ?? 8B 84 24 ??
            ?? ?? ?? 3D ?? ?? ?? ?? 0F 43 C1 6A ?? 50 53 FF 74 24 ?? E8 ?? ?? ?? ?? 83 F8 ?? 89
            44 24 ?? 75 ?? E8 ?? ?? ?? ?? 83 7C 24 ?? ?? 74 ?? 53 6A ?? FF 35 ?? ?? ?? ?? E8 ??
            ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 83 7C 24 ?? ?? 74 ?? FF 74 24 ?? 6A ?? FF 35 ?? ??
            ?? ?? E8 ?? ?? ?? ?? 83 7C 24 ?? ?? 8B 5C 24 ?? 0F 84 ?? ?? ?? ?? 80 BB ?? ?? ?? ??
            ?? 0F 85 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? EB
        }

        $enum_procs = {
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 39 F7 74 ??
            69 C7 ?? ?? ?? ?? 89 4D ?? 01 C8 68 ?? ?? ?? ?? 89 DE 53 50 E8 ?? ?? ?? ?? 83 C4 ??
            47 8D 85 ?? ?? ?? ?? 89 7D ?? 50 8B 5D ?? 53 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 45 ?? 89
            F3 89 C6 EB ?? 8D 4D ?? 89 F2 E8 ?? ?? ?? ?? 8B 4D ?? 8B 7D ?? EB ?? 31 FF 8B 75 ??
            85 FF 75 ?? E9 ?? ?? ?? ?? 31 FF 53 E8 ?? ?? ?? ?? 8B 75 ?? 85 FF 0F 84 ?? ?? ?? ??
            83 7D ?? ?? 0F 84 ?? ?? ?? ?? 69 C7 ?? ?? ?? ?? 8B 4D ?? 8D BD ?? ?? ?? ?? 01 F0 89
            45 ?? 8B 45 ?? 8D 04 40 8D 04 81 89 45 ?? EB
        }

        $find_files = {
            57 6A ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8B 85 ??
            ?? ?? ?? 89 45 ?? 68 ?? ?? ?? ?? 6A ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 53 56 E8 ?? ?? ??
            ?? 83 F8 ?? 89 45 ?? 0F 84 ?? ?? ?? ?? 89 75 ?? A1 ?? ?? ?? ?? 85 C0 75 ?? E8 ?? ??
            ?? ?? 85 C0 0F 84 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A ?? 6A ?? 50 E8 ?? ?? ?? ?? 85 C0 0F
            84 ?? ?? ?? ?? 89 C6 8B 45 ?? 8B 4D ?? 89 46 ?? 8B 45 ?? 89 46 ?? 8B 45 ?? 89 46 ??
            8D 41 ?? C7 06 ?? ?? ?? ?? C7 46 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 89 CB 50 E8 ?? ??
            ?? ?? 83 C4 ?? 8B 45 ?? 89 43 ?? 89 73 ?? 8B 75 ?? 31 C0 C7 43 ?? ?? ?? ?? ?? F7 45
            ?? ?? ?? ?? ?? 89 03 75 ?? 83 7D ?? ?? 74 ?? 57 6A ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ??
            ?? 83 7D ?? ?? 75 ?? 83 7D ?? ?? 74 ?? 83 7D ?? ?? 74 ?? FF 75 ?? 6A ?? FF 35 ?? ??
            ?? ?? E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? 5E 5F 5B 5D C3
        }

        $encrypt_files_p1 = {
            B8 ?? ?? ?? ?? 8D 4D ?? 8D 95 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 7D ?? 8B 75
            ?? 8D 4D ?? 89 FA 56 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 75 ?? 8B 45 ?? 8B 5D ?? 89
            45 ?? 8B 45 ?? 83 F8 ?? 72 ?? 85 DB 74 ?? 0F B7 0B 81 F9 ?? ?? ?? ?? 75 ?? 8B 4B ??
            89 C2 29 CA 72 ?? 83 FA ?? 72 ?? 85 DB 74 ?? 81 3C 0B ?? ?? ?? ?? 75 ?? 0F B7 54 0B
            ?? 81 FA ?? ?? ?? ?? 75 ?? 0F B7 54 0B ?? 83 EA ?? 89 55 ?? BA ?? ?? ?? ?? 19 D2 89
            55 ?? 72 ?? 83 F9 ?? 76
        }

        $encrypt_files_p2 = {
            53 E8 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 8B 5D ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 57
            6A ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 51 ?? 29 D0 8B 55 ?? 0F 92
            45 ?? 83 7D ?? ?? 75 ?? 80 7D ?? ?? 75 ?? 39 C2 77 ?? B8 ?? ?? ?? ?? F7 64 0B ?? 8B
            55 ?? 70 ?? 39 C2 72 ?? 8B 44 0B ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 89 45 ?? 8B 85 ??
            ?? ?? ?? 89 45 ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 55 ??
            89 45 ?? 89 10 89 48 ?? 8B 45 ?? 89 45 ?? 53 E8 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ??
            8B 45 ?? 8B 4D ?? 29 45 ?? 3B 4D ?? 0F 85 ?? ?? ?? ?? 8B 55 ?? 8D 4D ?? E8 ?? ?? ??
            ?? 8B 45 ?? 8B 4D ?? 89 45 ?? 89 4D ?? E9 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 35 ?? ??
            ?? ?? 8B 45 ?? F2 0F 10 45 ?? 85 F6 89 85 ?? ?? ?? ?? F2 0F 11 85 ?? ?? ?? ?? 0F 84
            ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 74 ?? 8D 0C C0 8D 3C 49 01 C7 01 F7 EB
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $enum_procs
        ) and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            all of ($remote_connection_p*)
        )
}
