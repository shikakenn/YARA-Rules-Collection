rule Win32_Ransomware_RegretLocker : tc_detection malicious
{
    meta:
        id = "7mHRFTPRRKqlLZN4dXBiFd"
        fingerprint = "v1_sha256_3927dfecacd74f60a169f82b68df5747daa90eaba77f24c5e730ce4c48d426a3"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects RegretLocker ransomware."
        category = "MALWARE"
        malware = "REGRETLOCKER"
        tc_detection_type = "Ransomware"
        tc_detection_name = "RegretLocker"
        tc_detection_factor = 5

    strings:

        $remote_connection_p1 = {
            55 8B EC 8B 41 ?? 8B 55 ?? 3B C2 72 ?? 2B C2 56 8B 75 ?? 3B C6 0F 42 F0 83 79 ?? ??
            72 ?? 8B 09 56 03 CA 51 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B C6 5E 5D C2 ?? ?? E8 ??
            ?? ?? ?? CC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 83 65 ?? ?? 8D 45 ?? 53
            56 57 50 E8 ?? ?? ?? ?? 83 65 ?? ?? 50 E8 ?? ?? ?? ?? 83 4D ?? ?? 8A D8 59 59 8D 4D
            ?? E8 ?? ?? ?? ?? 84 DB 0F 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ??
            C7 45 ?? ?? ?? ?? ?? 8B CC 6A ?? 83 61 ?? ?? C7 41 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 88
            19 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50
            E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 59 59 8B 8D ?? ?? ??
            ?? 8D 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 6A ?? 5B 3B CB C6 45 ?? ?? 0F 43 C2 80 78 ??
            ?? 75 ?? 3B CB 8D 85 ?? ?? ?? ?? 0F 43 C2 80 78 ?? ?? 75 ?? 3B CB 8D 85 ?? ?? ?? ??
            0F 43 C2 80 78 ?? ?? 75 ?? 3B CB 8D 85 ?? ?? ?? ?? 0F 43 C2 80 78 ?? ?? 75 ?? 3B CB
            8D 85 ?? ?? ?? ?? 0F 43 C2 80 78 ?? ?? 75 ?? 83 BD ?? ?? ?? ?? ?? 0F 84
        }

        $remote_connection_p2 = {
            8D 45 ?? 50 E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B C8 C7 04 24 ?? ?? ?? ?? E8 ?? ??
            ?? ?? 84 C0 75 ?? 8B BD ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 3B FB 8D B5 ?? ?? ?? ?? 8B 9D
            ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 0F 43 C3 83 FF ?? 0F 43 F3 0F 43 D3 33 C9 8A 40 ?? 3A
            46 ?? 0F BE 42 ?? 0F 94 C1 3B C8 75 ?? 83 FF ?? 8D 85 ?? ?? ?? ?? 0F 43 C3 80 78 ??
            ?? 75 ?? 83 FF ?? 8D 85 ?? ?? ?? ?? 0F 43 C3 80 78 ?? ?? 74 ?? 32 DB EB ?? B3 ?? F6
            45 ?? ?? 74 ?? 8D 4D ?? E8 ?? ?? ?? ?? 84 DB 74 ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ??
            ?? 6A ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 5F 6A ?? 33 DB 89 BD
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8
            ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 89 65 ?? 53 89 59 ?? 89 79 ?? 68 ?? ?? ?? ??
            88 19 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 8D 85 ?? ?? ?? ?? 50 89 59 ?? 89 59
            ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ??
            8B B5 ?? ?? ?? ?? C6 45 ?? ?? 83 FE ?? 77 ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ??
            ?? ?? ?? 84 C0 74 ?? 6A ?? 5E 83 EC ?? 8B CC 89 65 ?? 53 89 59 ?? 89 79 ?? 68 ?? ??
            ?? ?? 88 19 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 8D 85 ?? ?? ?? ?? 50 89 59 ??
            89 59 ?? E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50
        }

        $remote_connection_p3 = {
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ??
            ?? ?? 83 EE ?? 75 ?? 8B B5 ?? ?? ?? ?? 8D 46 ?? 83 F8 ?? 77 ?? 68 ?? ?? ?? ?? 8D 8D
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ??
            ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 50 68 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 59 59 89 5D ?? 89 7D ?? 88 9D ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? 89
            5D ?? 89 5D ?? E8 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 59 8B
            F0 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? 89 5D ?? 89 7D ?? 88 5D ?? E8 ?? ?? ??
            ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 56 83 C1 ??
            E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? FF 35 ??
            ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 59 59 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? C6 45
        }

        $remote_connection_p4 = {
            89 5D ?? 89 7D ?? 88 5D ?? E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 8D 4D
            ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 45 ?? 50 83 C1 ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ??
            ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 51 51 8B CC 89 65 ?? 8D 45 ?? C7 85 ?? ?? ??
            ?? ?? ?? ?? ?? 50 8D 45 ?? 89 4D ?? 50 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 6A
            ?? 89 59 ?? C7 41 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 88 19 E8 ?? ?? ?? ?? 8D 45 ?? C6 45
            ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D
            ?? E8 ?? ?? ?? ?? 8B 75 ?? 85 F6 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ??
            E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 0F 43 85
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 56 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 74 ?? 50 53 8D
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 85 ?? ?? ?? ?? 8B 75 ?? 0F 43 85 ?? ??
            ?? ?? 6A ?? 6A ?? 56 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 74 ?? 40 8D 8D ?? ?? ?? ??
            50 E8 ?? ?? ?? ?? 8B 75 ?? 56 E8 ?? ?? ?? ?? 59 53 FF 75 ?? 8D 8D ?? ?? ?? ?? A3 ??
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 4D ?? A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 88 1C 01 E8 ?? ??
            ?? ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 59 8B 75 ??
            8D 4D ?? C6 45 ?? ?? FF 76 ?? E8 ?? ?? ?? ?? 8B 45 ?? C6 45 ?? ?? 89 70 ?? 8B 45 ??
            89 30 8B 45 ?? 89 70 ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 58 50 68 ?? ?? ?? ?? 83 EC ?? 89
        }

        $remote_connection_p5 = {
            5D ?? 8B CC FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B F8 6A ?? 58
            FF 35 ?? ?? ?? ?? 85 FF 0F 44 F8 8D 45 ?? 50 E8 ?? ?? ?? ?? 59 59 6A ?? 5E 6A ?? 68
            ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? 89 5D ?? 89 75 ?? 88 5D ?? E8 ?? ?? ?? ?? 8D 45 ??
            C6 45 ?? ?? 50 8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 45 ?? 50 83 C1 ?? E8
            ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ??
            ?? ?? ?? 8D 4D ?? 89 5D ?? 89 75 ?? 88 5D ?? E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50
            8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 85 ?? ?? ?? ?? 50 83 C1 ?? E8 ?? ??
            ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 59 8B F0 6A ??
            68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? 89 5D ?? C7 45 ?? ?? ?? ?? ?? 88 5D ?? E8 ?? ??
            ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 56 83 C1
            ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 45
            ?? 50 E8 ?? ?? ?? ?? 59 8B F0 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? 89 5D ?? C7
            45 ?? ?? ?? ?? ?? 88 5D ?? E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 8D 4D
            ?? E8 ?? ?? ?? ?? 8B 4D ?? 56 83 C1 ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D
            ?? C6 45 ?? ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 45 ?? 57 50 E8 ?? ?? ?? ?? 83 C4
            ?? 8B F0 6A ?? 58 6A ?? 5F 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? 88 45 ?? 89 5D ?? 89 7D ??
            88 5D ?? E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 8D 4D ?? E8 ?? ?? ?? ??
            8B 4D ?? 56 83 C1 ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8
            ?? ?? ?? ?? 51 51 8B CC 89 65 ?? 8D 45 ?? 89 4D ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83
            EC ?? C6 45 ?? ?? 8B CC 6A ?? 89 59 ?? 89 79 ?? 68 ?? ?? ?? ?? 88 19 E8
        }

        $encrypt_files_p1 = {
            8B FB 89 5D ?? 89 7D ?? 89 5D ?? 8B 85 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? C6 45 ?? ?? 89
            45 ?? 3B F0 74 ?? 56 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 3B DF 74 ??
            8B 08 89 0F 8B 48 ?? 89 4F ?? 83 20 ?? 83 60 ?? ?? 83 C7 ?? 89 7D ?? EB ?? 50 57 8D
            4D ?? E8 ?? ?? ?? ?? 8B 5D ?? 8B 7D ?? 83 7D ?? ?? C6 45 ?? ?? 0F 85 ?? ?? ?? ?? 6A
            ?? 58 03 F0 3B 75 ?? 75 ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 8B B5 ?? ?? ?? ??
            C6 45 ?? ?? 8B 06 89 45 ?? EB ?? 8D 48 ?? 8D 41 ?? 50 51 68 ?? ?? ?? ?? 8D 4D ?? E8
            ?? ?? ?? ?? C6 45 ?? ?? 3B DF 74 ?? 8B 08 89 0F 8B 48 ?? 89 4F ?? 83 20 ?? 83 60 ??
            ?? 83 C7 ?? 89 7D ?? EB ?? 50 57 8D 4D ?? E8 ?? ?? ?? ?? 8B 5D ?? 8B 7D ?? 83 7D ??
            ?? C6 45 ?? ?? 0F 85 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 45 ?? 3B C6 75 ?? 8B 75
            ?? EB ?? 83 7E ?? ?? 74 ?? 8B CE E8 ?? ?? ?? ?? 83 C6 ?? 3B F7 75 ?? 0F 57 C0 68 ??
            ?? ?? ?? 66 0F 13 45 ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 6A ?? 59 99
            F7 F9 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 ?? 8B 1D ?? ?? ?? ?? 8B
            75 ?? 8B 7D ?? 89 45 ?? 3B D8 74 ?? 83 EC ?? 8B CC 53 83 61 ?? ?? 83 61 ?? ?? E8 ??
            ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 03 F8 83 D6 ?? 6A ?? 58 03 D8 3B 5D ?? 75 ?? 0F AC
            F7 ?? C1 EE ?? 56 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 83 C4 ?? 8B 35
            ?? ?? ?? ?? EB ?? 83 7E ?? ?? 8B C6 72 ?? 8B 06 6A ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ??
            ?? 83 C4 ?? 6A ?? 58 03 F0 3B F7 75 ?? 68 ?? ?? ?? ?? E8
        }

        $encrypt_files_p2 = {
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 53 56 8B 75 ?? 8D 8D ?? ?? ?? ?? 57
            56 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 33 DB 50 8D 45 ?? 89 5D ?? 50 E8 ?? ?? ?? ?? 59
            59 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8B CC 6A ?? 89 59 ?? C7 41
            ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 88 19 E8 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4
            ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? 8D 4D ?? 8A D8 E8 ?? ?? ?? ?? 84 DB 74 ?? 33 DB E9 ??
            ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 68 ?? ?? ?? ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 59 59 85
            C0 0F 84 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 68 ?? ?? ?? ?? 0F 43 45 ?? 50 E8 ?? ?? ??
            ?? 59 59 85 C0 0F 84 ?? ?? ?? ?? 83 EC ?? 33 DB 8B CC 89 5D ?? 56 E8 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 83 C4 ?? 89 45 ?? B9 ?? ?? ?? ?? BF ?? ?? ?? ?? 3B C1 0F 42 C8 3B C7 89
            4D ?? 0F 42 F8 89 7D ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 56 8D 8D ?? ?? ??
            ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 39 9D ?? ?? ?? ?? 75 ?? 83 EC ?? 8B CC 56 E8 ?? ?? ??
            ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 83 7E ?? ?? C6 45 ?? ?? 72 ?? 8B 36 E8
            ?? ?? ?? ?? FF 30 E8 ?? ?? ?? ?? 56 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D
            ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 77 ?? 56 E8 ?? ?? ?? ?? 56 89 45 ?? E8 ?? ?? ??
            ?? 8B 4D ?? 56 53 51 89 45 ?? E8 ?? ?? ?? ?? 56 53 FF 75 ?? E8 ?? ?? ?? ?? 8B 45 ??
            83 C4 ?? 89 5D ?? 8B D3 85 C0 0F 84 ?? ?? ?? ?? 8B C8 2B CA 39 4D ?? 8B C1 8B F1 0F
            46 45 ?? 3B F9 89 45 ?? 0F 46 F7 8B 7D ?? 2B CE 89 75 ?? 39 4D ?? 0F 46 4D ?? 89 4D
            ?? 85 FF 75 ?? 53 56 FF 75 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 0C 3E 8B
        }

        $encrypt_files_p3 = {
            C4 89 4D ?? 89 08 8D 8D ?? ?? ?? ?? 89 58 ?? 89 58 ?? 89 58 ?? 89 58 ?? 89 58 ?? E8
            ?? ?? ?? ?? 53 FF 75 ?? 8D 8D ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 8D 45 ?? 50 FF 75
            ?? 8D 8D ?? ?? ?? ?? FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 8B 4D ?? 83 EC ?? 8B D4 8B D8
            33 C0 03 CF 89 0A 8D 8D ?? ?? ?? ?? 89 42 ?? 89 42 ?? 89 42 ?? 89 42 ?? 89 42 ?? E8
            ?? ?? ?? ?? 6A ?? FF 75 ?? 8D 8D ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 7D ?? 2B 75 ?? 03
            7D ?? 56 57 E8 ?? ?? ?? ?? 59 59 6A ?? 56 57 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 75
            ?? FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? 01 45 ?? 53 E8 ?? ?? ?? ?? 8B
            85 ?? ?? ?? ?? 83 C4 ?? 8B 40 ?? 8B 84 05 ?? ?? ?? ?? C1 E8 ?? A8 ?? 74 ?? 83 EC ??
            8B CC FF 75 ?? E8 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 83 7E ?? ??
            C6 45 ?? ?? 72 ?? 8B 36 E8 ?? ?? ?? ?? FF 30 E8 ?? ?? ?? ?? 56 50 68 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 8B 7D ??
            89 55 ?? 6A ?? 5B 3B D0 0F 82 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 75 ??
            E8 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 59 59 FF 75 ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 EC
            ?? C6 45 ?? ?? 8B CC 6A ?? 89 59 ?? C7 41 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 88 19 E8 ??
            ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 78 ?? ?? 8B 48 ?? C6 45 ?? ?? 72 ??
            8B 00 51 50 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ??
            8D 45 ?? 0F 43 45 ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 8B CC 50 89 59 ??
            89 59 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? B3 ?? E8 ?? ?? ?? ?? 8D 8D
            ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? FF 75 ?? 56 E8 ?? ?? ?? ?? 59 59 8A D8 8D 4D ?? E8
            ?? ?? ?? ?? 8B 4D ?? 8A C3 5F 5E 64 89 0D ?? ?? ?? ?? 5B C9 C3
        }

        $find_files = {
            8B FF 55 8B EC 51 8B 4D ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA 83 C8 ?? 57 8B 7D ??
            41 2B C7 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 53 56 8D 5F ?? 03 D9 6A ?? 53 E8 ?? ??
            ?? ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ??
            FF 75 ?? 2B DF 8D 04 3E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8B 4D ??
            56 E8 ?? ?? ?? ?? 6A ?? 8B F0 E8 ?? ?? ?? ?? 59 8B C6 5E 5B 5F 8B E5 5D C3 33 C0 50
            50 50 50 50 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5
            89 45 ?? 8B 4D ?? 53 8B 5D ?? 56 8B 75 ?? 57 89 B5 ?? ?? ?? ?? EB ?? 8A 01 3C ?? 74
            ?? 3C ?? 74 ?? 3C ?? 74 ?? 51 53 E8 ?? ?? ?? ?? 59 59 8B C8 3B CB 75 ?? 8A 11 80 FA
            ?? 75 ?? 8D 43 ?? 3B C8 74 ?? 56 33 FF 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 33 FF
            80 FA ?? 74 ?? 80 FA ?? 74 ?? 80 FA ?? 74 ?? 8B C7 EB ?? 33 C0 40 0F B6 C0 2B CB 41
            F7 D8 68 ?? ?? ?? ?? 1B C0 23 C1 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 E8 ?? ??
            ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 57 57 57 50 57 53 FF 15 ?? ?? ?? ?? 8B F0 8B 85 ??
            ?? ?? ?? 83 FE ?? 75 ?? 50 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 83 FE ?? 74 ?? 56
            FF 15 ?? ?? ?? ?? 8B C7 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 48 ??
            2B 08 C1 F9 ?? 89 8D ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 8A 8D ?? ?? ?? ?? 84 C9
            74 ?? 80 F9 ?? 75 ?? 80 BD ?? ?? ?? ?? ?? 74 ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ??
            ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ??
            ?? 85 C0 8B 85 ?? ?? ?? ?? 75 ?? 8B 10 8B 40 ?? 8B 8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B
            C8 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4
            ?? E9
        }

    condition:
        uint16(0) == 0x5A4D and
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
