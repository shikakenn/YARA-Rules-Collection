rule Win32_Ransomware_WinWord64 : tc_detection malicious
{
    meta:
        id = "48f5vUSo5VYtBvNhUhxics"
        fingerprint = "v1_sha256_73d8c4f1b3bed365320b26332f1f1b49404d8e6536f3e25042f5f64e5bc09bd4"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects WinWord64 ransomware."
        category = "MALWARE"
        malware = "WINWORD64"
        tc_detection_type = "Ransomware"
        tc_detection_name = "WinWord64"
        tc_detection_factor = 5

    strings:

        $remote_connection_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? A1 ?? ?? ?? 
            ?? 33 DB 83 3D ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 0F 43 0D ?? ?? ?? ?? 
            03 C1 89 9D ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 0F 43 0D ?? ?? ?? ?? 51 
            50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 53 89 5D ?? 8D 85 ?? ?? ?? ?? 83 BD ?? ?? 
            ?? ?? ?? 53 0F 43 85 ?? ?? ?? ?? 6A ?? 50 FF 15 ?? ?? ?? ?? 8B D8 89 9D ?? ?? ?? ?? 
            85 DB 0F 84 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? A1 ?? ?? ?? ?? 0F 43 0D 
            ?? ?? ?? ?? 03 C1 83 3D ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 0F 43 0D ?? ?? ?? ?? 51 50 51 
            8D 4D ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 6A ?? 0F 43 45 ?? 68 ?? ?? ?? ?? 50 53 
            FF 15 ?? ?? ?? ?? 8B 55 ?? 8B D8 89 9D ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 
            ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 
            76 ?? FF 15 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? 66 89 45 ?? 85 DB 0F 84 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? B9 ?? ?? 
            ?? ?? A1 ?? ?? ?? ?? 0F 43 0D ?? ?? ?? ?? 03 C1 83 3D ?? ?? ?? ?? ?? B9
        }

        $remote_connection_p2 = { 
            0F 43 0D ?? ?? ?? ?? 51 50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D BD ?? 
            ?? ?? ?? 83 BD ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? A1 ?? ?? ?? ?? 0F 43 BD ?? ?? ?? ?? 83 
            3D ?? ?? ?? ?? ?? 0F 43 0D ?? ?? ?? ?? 03 C1 83 3D ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 0F 
            43 0D ?? ?? ?? ?? 51 50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 85 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 50 57 53 FF 15 ?? ?? ?? 
            ?? 8B 55 ?? 89 85 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 
            8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 88 45 ?? 8B 95 ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? 
            ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 76 ?? 
            FF 15 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? 
            ?? ?? C6 45 ?? ?? 8D 4D ?? 83 7D ?? ?? 8B 45 ?? 0F 43 4D ?? 03 C1 83 7D ?? ?? 8D 4D 
            ?? 0F 43 4D ?? 51 50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 85 ?? ?? ?? 
            ?? 83 BD ?? ?? ?? ?? ?? 8D 4D ?? 68 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 89 85 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? B9 ?? ?? 
            ?? ?? 83 3D ?? ?? ?? ?? ?? 8B 75 ?? 8B C6 0F 43 0D ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 8B
        }

        $remote_connection_p3 = {
            55 ?? 2B C2 57 51 3B F8 77 ?? 8D 04 3A 83 FE ?? 89 45 ?? 8D 45 ?? 0F 43 45 ?? 8D 34 
            10 56 E8 ?? ?? ?? ?? 83 C4 ?? C6 04 37 ?? EB ?? C6 85 ?? ?? ?? ?? ?? 8D 4D ?? FF B5 
            ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 75 ?? 8B C6 
            8B BD ?? ?? ?? ?? 0F 43 CF 8B 55 ?? 2B C2 8B 9D ?? ?? ?? ?? 53 51 3B D8 77 ?? 8D 04 
            1A 83 FE ?? 89 45 ?? 8D 45 ?? 0F 43 45 ?? 8D 34 10 56 E8 ?? ?? ?? ?? 83 C4 ?? C6 04 
            1E ?? EB ?? C6 85 ?? ?? ?? ?? ?? 8D 4D ?? FF B5 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B BD 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? B9 ?? ?? ?? ?? 83 3D ?? ?? 
            ?? ?? ?? 8B 75 ?? 8B C6 0F 43 0D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B 55 ?? 2B C2 53 51 
            3B D8 77 ?? 8D 04 1A 83 FE ?? 89 45 ?? 8D 45 ?? 0F 43 45 ?? 8D 34 10 56 E8 ?? ?? ?? 
            ?? 83 C4 ?? C6 04 33 ?? EB ?? C6 85 ?? ?? ?? ?? ?? 8D 4D ?? FF B5 ?? ?? ?? ?? 53 E8 
            ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8B 45 ?? 0F 43 
            D3 8B 75 ?? 2B C6 8B 8D ?? ?? ?? ?? 51 52 3B C8 77 ?? 83 7D ?? ?? 8D 04 0E 89 45 ?? 
            8D 45 ?? 0F 43 45 ?? 03 F0 56 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 C4 ?? C6 04 06 ?? 
            EB ?? C6 85 ?? ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 8B 9D ?? ?? 
            ?? ?? 83 3D ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 0F 43 15 ?? ?? ?? ?? 8B
        }

        $remote_connection_p4 = {
            45 ?? 8B 75 ?? 2B C6 89 8D ?? ?? ?? ?? 51 52 3B C8 77 ?? 83 7D ?? ?? 8D 04 0E 89 45 
            ?? 8D 45 ?? 0F 43 45 ?? 03 F0 56 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 C4 ?? C6 04 30 
            ?? EB ?? C6 85 ?? ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 8B 95 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8B D0 83 78 ?? ?? 72 ?? 8B 10 
            8B 48 ?? 8B 45 ?? 8B 75 ?? 2B C6 89 8D ?? ?? ?? ?? 51 52 3B C8 77 ?? 83 7D ?? ?? 8D 
            04 0E 89 45 ?? 8D 45 ?? 0F 43 45 ?? 03 F0 56 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 C4 
            ?? C6 04 30 ?? EB ?? C6 85 ?? ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? 
            ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? 
            ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 76 ?? FF 15 ?? ?? ?? ?? 52 
            51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? BA ?? ?? ?? ?? 83 3D 
            ?? ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 0F 43 15 ?? ?? ?? ?? 8B 45 ?? 8B 75 ?? 2B C6 89 8D 
            ?? ?? ?? ?? 51 52 3B C8 77 ?? 83 7D ?? ?? 8D 04 0E 89 45 ?? 8D 45 ?? 0F 43 45 ?? 03 
            F0 56 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 C4 ?? C6 04 30 ?? EB ?? C6 85 ?? ?? ?? ?? 
            ?? FF B5 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 55 ?? 8B 4D ?? 0F 43 
            55 ?? 8B 45 ?? 8B 75 ?? 2B C6 89 8D ?? ?? ?? ?? 51 52 3B C8 77 ?? 83 7D ?? ?? 8D 04 
            0E 89 45 ?? 8D 45 ?? 0F 43 45 ?? 03 F0 56 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 C4 ?? 
            C6 04 30 ?? EB ?? C6 85 ?? ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 
            83 3D ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 0F 43 15 ?? ?? ?? ?? 8B 45 ?? 
            8B 75 ?? 2B C6 89 8D ?? ?? ?? ?? 51 52 3B C8 77 ?? 83 7D ?? ?? 8D 04 31 89 45 ?? 8D
        }

        $remote_connection_p5 = {
            45 ?? 0F 43 45 ?? 03 F0 56 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 C4 ?? C6 04 30 ?? EB 
            ?? C6 85 ?? ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 8B B5 ?? ?? ?? 
            ?? 85 F6 74 ?? 8B 45 ?? 8D 4D ?? 83 7D ?? ?? 6A ?? 0F 43 4D ?? 50 50 51 6A ?? FF B5 
            ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 8D 8D ?? 
            ?? ?? ?? 51 68 ?? ?? ?? ?? 50 6A ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 F6 8B 35 ?? 
            ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 50 FF D6 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 50 FF D6 8B 
            85 ?? ?? ?? ?? 85 C0 74 ?? 50 FF D6 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA 
            ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 8B 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            C6 45 ?? ?? 83 F8 ?? 72 ?? 8D 48 ?? 8B C3 81 F9 ?? ?? ?? ?? 72 ?? 8B 5B ?? 83 C1 ?? 
            2B C3 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 51 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B 85 ?? ?? 
            ?? ?? 83 F8 ?? 72 ?? 8D 48 ?? 8B C7 81 F9 ?? ?? ?? ?? 72 ?? 8B 7F ?? 83 C1 ?? 2B C7
        }

        $remote_connection_p6 = { 
            83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 51 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 83 FA ?? 
            72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 
            F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 95 ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 
            ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 
            0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 
            42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 
            51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 95 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? 
            ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 76 ?? FF 15 ?? ?? ?? ?? 52 
            51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD 
            E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $encrypt_files_p1 = {
            FF 15 ?? ?? ?? ?? 83 7D ?? ?? 8D 55 ?? 8B 4D ?? 0F 43 55 ?? 03 CA 89 85 ?? ?? ?? ?? 
            83 7D ?? ?? 8D 45 ?? 51 0F 43 45 ?? 51 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 83 
            7F ?? ?? 72 ?? 8B 3F 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? 
            ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 76 
            ?? FF 15 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? 83 7D ?? ?? 8D 4D ?? 66 89 85 ?? ?? ?? ?? 0F 43 4D ?? 8B 45 ?? 03 C1 C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? 0F 43 4D ?? 51 50 51 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B F0 83 7E ?? ?? 72 ?? 8B 36 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? 
            ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 
            C0 ?? 83 F8 ?? 76 ?? FF 15 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6A ?? 50 6A ?? 68 ?? ?? ?? ?? 57 8B 3D ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? FF D7 89 85 ?? ?? ?? ?? 83 
            F8 ?? 0F 84 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 56 FF 
            D7 89 85 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C9 BA
        }

        $encrypt_files_p2 = {
            8D 40 ?? F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? BA ?? ?? 
            ?? ?? 8B 0D ?? ?? ?? ?? 0F 43 15 ?? ?? ?? ?? 03 CA 89 85 ?? ?? ?? ?? 83 3D ?? ?? ?? 
            ?? ?? B8 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 0F 43 05 ?? ?? ?? ?? 51 50 8B CE E8 ?? ?? ?? 
            ?? A1 ?? ?? ?? ?? 83 C4 ?? 33 C9 68 ?? ?? ?? ?? 6A ?? 56 66 89 0C 46 8D 85 ?? ?? ?? 
            ?? 51 50 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A ?? FF B5 ?? 
            ?? ?? ?? FF 15 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 42 
            8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? 
            ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 
            C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C7 45 ?? 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 FA ?? 0F 82 ?? ?? ?? ?? 8B 4D ?? 42 
            8B C1 81 FA ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 
            0F 86 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 
            FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? FF B5 ?? ?? ?? ?? 
            8D 45 ?? 50 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? E9 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 6A ?? FF B5 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? 
            ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 
            50 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 33 FF 33 F6 57 FF B5 ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 57 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84
        }

        $encrypt_files_p3 = {
            8B 85 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 03 F8 8D 85 ?? ?? ?? ?? 3B 
            BD ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 0F 44 F1 50 6A ?? 56 6A ?? FF B5 ?? ?? ?? ?? FF 
            15 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 
            FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 
            ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? 
            ?? 6A ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            B9 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 6A ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF B5 ?? ?? ?? 
            ?? 8B 35 ?? ?? ?? ?? FF D6 FF B5 ?? ?? ?? ?? FF D6 C6 85 ?? ?? ?? ?? ?? E9 ?? ?? ?? 
            ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8A 85 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 
            5F 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $find_files = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B F9 89 BD ?? ?? ?? ?? 33 C0 89 
            85 ?? ?? ?? ?? 38 47 ?? 0F 85 ?? ?? ?? ?? 8B 07 8B 08 8D 85 ?? ?? ?? ?? 50 8D 49 ?? 
            E8 ?? ?? ?? ?? 83 38 ?? 0F 85 ?? ?? ?? ?? 83 7F ?? ?? 74 ?? 8B 07 8B 08 8D 85 ?? ?? 
            ?? ?? 50 8D 49 ?? E8 ?? ?? ?? ?? 83 38 ?? 0F 84 ?? ?? ?? ?? 8B 07 8D 8D ?? ?? ?? ?? 
            8B 30 8D 46 ?? 50 E8 ?? ?? ?? ?? 8D 46 ?? C7 45 ?? ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? B8 ?? ?? ?? 
            ?? 8B 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? 
            ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 76 
            ?? FF 15 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 07 8B 
            30 8B 46 ?? 8B 00 85 C0 74 ?? 8D 8D ?? ?? ?? ?? 51 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? 
            ?? ?? ?? 83 C4 ?? 66 83 38 ?? 75 ?? 8B 46 ?? FF 30 FF 15 ?? ?? ?? ?? 8B 46 ?? 83 C4 
            ?? C7 00 ?? ?? ?? ?? EB ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 
            4E ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? C6 45 ?? ?? 81 7F ?? ?? ?? ?? ?? 8B 37 8B 36 75 ?? 68 ?? ?? ?? ?? FF 15 
            ?? ?? ?? ?? 8B 46 ?? 89 85 ?? ?? ?? ?? 89 BD ?? ?? ?? ?? C6 45 ?? ?? 6A ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 8D 85 ?? ?? ?? ?? 8D 4F ?? 50 E8
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
