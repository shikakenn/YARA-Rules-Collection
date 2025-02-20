rule Win32_Ransomware_Major : tc_detection malicious
{
    meta:
        id = "36DKBftXAGTNOk17CNLWVp"
        fingerprint = "v1_sha256_16fb7763e3806fca6937fef7e8b3d8bccd61cb39549061d359d630c7d266c270"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Major ransomware."
        category = "MALWARE"
        malware = "MAJOR"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Major"
        tc_detection_factor = 5

    strings:
        $find_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 33 C0 89 4D ?? 57 50 66 89 45 ?? 8D 8D ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 0F 57 C0 C7 45 ?? ?? ?? ?? ?? 50 C7 45 ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 
            ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? ?? ?? ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            8B 40 ?? C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 
            0D ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 8D 4D ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 33 C9 8B F8 51 89 4D ?? 51 8D 4D ?? 89 7D ?? E8 ?? ?? ?? ?? 89 45 ?? 8D 4D ?? 
            8D 45 ?? 50 FF 77 ?? 57 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 47 ?? 89 4D ?? BB ?? ?? ?? 
            ?? 8B 48 ?? 89 01 8B 07 8D 4D ?? 83 C0 ?? 3B C8 74 ?? 6A ?? 6A ?? 50 E8 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 8D 45 ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 8D 45 ?? 3B C6
        }

        $find_files_p2 = {
            0F 84 ?? ?? ?? ?? 8B 45 ?? 83 F8 ?? 72 ?? 8B 4D ?? 40 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? 
            ?? 03 C0 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 0F 85 ?? ?? ?? ?? 8B 41 ?? 3B C1 0F 83 ?? ?? 
            ?? ?? 2B C8 83 F9 ?? 0F 82 ?? ?? ?? ?? 83 F9 ?? 0F 87 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 33 C0 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 83 7E ?? 
            ?? 73 ?? 8B 46 ?? 83 C0 ?? 74 ?? 03 C0 50 8D 45 ?? 56 50 E8 ?? ?? ?? ?? 83 C4 ?? EB 
            ?? 8B 06 89 45 ?? C7 06 ?? ?? ?? ?? 8B 46 ?? 89 45 ?? 8B 46 ?? 89 45 ?? C7 46 ?? ?? 
            ?? ?? ?? 83 7E ?? ?? C7 46 ?? ?? ?? ?? ?? 72 ?? 8B 36 33 C0 66 89 06 8B 45 ?? 83 F8 
            ?? 72 ?? 8B 4D ?? 40 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 03 C0 3D ?? ?? ?? ?? 72 ?? F6 
            C1 ?? 0F 85 ?? ?? ?? ?? 8B 41 ?? 3B C1 0F 83 ?? ?? ?? ?? 2B C8 83 F9 ?? 0F 82 ?? ?? 
            ?? ?? 83 F9 ?? 0F 87 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 3F 8D 77 ?? 8B 
            4F ?? 8B 07 89 01 8B 0F 8B 47 ?? 89 41 ?? 8B 45 ?? 48 89 45 ?? 89 45 ?? 8B 46 ?? 83 
            F8 ?? 72 ?? 8B 0E 40 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 03 C0 3D ?? ?? ?? ?? 72 ?? F6
        }

        $find_files_p3 = {
            C1 ?? 0F 85 ?? ?? ?? ?? 8B 41 ?? 3B C1 0F 83 ?? ?? ?? ?? 2B C8 83 F9 ?? 0F 82 ?? ?? 
            ?? ?? 83 F9 ?? 0F 87 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 46 ?? ?? ?? ?? 
            ?? 83 7E ?? ?? C7 46 ?? ?? ?? ?? ?? 72 ?? 8B 36 33 C0 57 66 89 06 E8 ?? ?? ?? ?? 83 
            C4 ?? 8D 8D ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 0F 43 45 ?? 51 50 FF 15 ?? ?? ?? ?? 8B 
            F8 89 7D ?? 83 FF ?? 0F 84 ?? ?? ?? ?? 66 66 66 0F 1F 84 00 ?? ?? ?? ?? 33 C0 C7 45 
            ?? ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 0F 84 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 8B 08 85 C9 74 ?? 8B 85 ?? ?? ?? ?? 8B 00 8D 14 41 EB ?? 8B 85 
            ?? ?? ?? ?? 8B 08 8B 85 ?? ?? ?? ?? 8B 00 8D 14 48 8B 85 ?? ?? ?? ?? 8B 08 2B D1 D1 
            FA 81 FA ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 8D 04 12 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 0F 85 
            ?? ?? ?? ?? 8B 41 ?? 3B C1 0F 83 ?? ?? ?? ?? 2B C8 83 F9 ?? 0F 82 ?? ?? ?? ?? 83 F9 
            ?? 0F 87 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? C7 00 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? C7 00 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? C7 00 
            ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? C7 00 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? C7 00 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? C7 00 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 E0 ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? 50 89 85 ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 F8 ?? 72
            ?? 8B 4D ?? 40 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 03 C0 3D ?? ?? ?? ?? 72 ?? F6 C1
        }

        $find_files_p4 = { 
            0F 85 ?? ?? ?? ?? 8B 41 ?? 3B C1 0F 83 ?? ?? ?? ?? 2B C8 83 F9 ?? 0F 82 ?? ?? ?? ?? 
            83 F9 ?? 0F 87 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 68 
            ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 EC ?? F6 85 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? 
            ?? 8B D4 33 C0 C7 42 ?? ?? ?? ?? ?? C7 42 ?? ?? ?? ?? ?? 66 89 02 66 39 85 ?? ?? ?? 
            ?? 75 ?? 33 C9 EB ?? 8D 8D ?? ?? ?? ?? 8D 71 ?? 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B 
            CE D1 F9 51 8D 85 ?? ?? ?? ?? 8B CA 50 E8 ?? ?? ?? ?? 8B 4D ?? E8 ?? ?? ?? ?? 85 C0 
            0F 84 ?? ?? ?? ?? 6A ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? C7 45 ?? 
            ?? ?? ?? ?? 66 89 45 ?? E8 ?? ?? ?? ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 83 CB ?? C7 45 ?? 
            ?? ?? ?? ?? 66 89 45 ?? 66 39 85 ?? ?? ?? ?? 75 ?? 33 C9 EB ?? 8D 8D ?? ?? ?? ?? 8D 
            51 ?? 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 51 8D 85 ?? ?? ?? ?? 50 8D 4D ?? 
            E8 ?? ?? ?? ?? 8D 45 ?? 83 CB ?? 50 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 
            0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85
        }

        $find_files_p5 = {
            83 CB ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 CB ?? 50 8D 85 ?? 
            ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 CB ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 83 CB ?? 50 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 85 C0 74 ?? 
            C6 45 ?? ?? F6 C3 ?? 74 ?? 8B 45 ?? 83 E3 ?? 83 F8 ?? 72 ?? 40 8D 4D ?? 50 FF 75 ?? 
            E8 ?? ?? ?? ?? 33 C0 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? F6 C3 ?? 
            74 ?? 8B 85 ?? ?? ?? ?? 83 E3 ?? 83 F8 ?? 72 ?? 40 8D 8D ?? ?? ?? ?? 50 FF B5 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? 66 89 85 ?? ?? ?? ?? F6 C3 ?? 74 ?? 8B 85 ?? ?? ?? ?? 83 E3 ?? 83 F8 ?? 72 ?? 40 
            8D 8D ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? F6 C3 ?? 74 ?? 8B 85 ?? ?? 
            ?? ?? 83 E3 ?? 83 F8 ?? 72 ?? 40 8D 8D ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? 
            ?? ?? 8B 45 ?? 83 E3 ?? 83 F8 ?? 72 ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 33 C0
        }

        $find_files_p6 = {
            C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? 83 E3 ?? 8B 45 ?? C7 45 ?? ?? ?? ?? ?? 83 F8 ?? 72 
            ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 80 7D ?? ?? 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 75 ?? 8D 45 ?? 50 8D 4D ?? FF 76 ?? 56 E8 ?? ?? 
            ?? ?? 8B 55 ?? B9 ?? ?? ?? ?? 2B CA 83 F9 ?? 0F 82 ?? ?? ?? ?? 89 46 ?? 42 8B 48 ?? 
            89 55 ?? 89 01 E9 ?? ?? ?? ?? 8D 45 ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 75 ?? 
            8D 45 ?? 50 8D 4D ?? FF 76 ?? 56 E8 ?? ?? ?? ?? 8B 55 ?? B9 ?? ?? ?? ?? 2B CA 83 F9 
            ?? 0F 82 ?? ?? ?? ?? 89 46 ?? 42 8B 48 ?? 89 55 ?? 89 55 ?? 89 01 8B 45 ?? 83 F8 ?? 
            72 ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 8D ?? ?? ?? ?? 54 E8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 8D 85 ?? ?? ?? ?? 8B CC 50 E8 ?? ?? ?? ?? 8B 75 
            ?? 8B CE E8 ?? ?? ?? ?? 85 C0 74 ?? 8D 45 ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 
            45 ?? 8B CE 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 F8 ?? 72 ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 7D ?? 
            8B CF E8 ?? ?? ?? ?? 8B 4D ?? 85 C9 74 ?? 8B 7D ?? E9 ?? ?? ?? ?? 8B 4D ?? 85 C9 0F 
            84 ?? ?? ?? ?? 0F 1F 00 8B 45 ?? 8D 4D ?? 8B 00 83 C0 ?? 3B C8 74 ?? 6A ?? 6A ?? 50 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B F0 83 C4
        }

        $find_files_p7 = {
            8D 45 ?? 3B C6 74 ?? 8B 4D ?? 83 F9 ?? 72 ?? 41 51 FF 75 ?? 8B C8 E8 ?? ?? ?? ?? 33 
            C0 C7 45 ?? ?? ?? ?? ?? 56 8D 4D ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? E8 ?? ?? ?? ?? 
            8B 45 ?? 83 F8 ?? 72 ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? 83 7D ?? ?? 8D 8D ?? ?? ?? ?? 8D 45 ?? 0F 43 45 ?? 51 50 FF 15 ?? ?? ?? ?? 8B 75 
            ?? 89 45 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 0F 1F 00 33 C0 C7 45 ?? ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 45 ?? 
            6A ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 83 F8 ?? 72 ?? 40 8D 4D ?? 50 FF 
            75 ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            8D 85 ?? ?? ?? ?? 83 EC ?? F6 85 ?? ?? ?? ?? ?? 8B CC 50 0F 84 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B CF E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 50 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8B 5D ?? 8D 45 ?? 50 8D 4D ?? FF 73 ?? 53 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 
            2B CE 83 F9 ?? 0F 82 ?? ?? ?? ?? 89 43 ?? 46 8B 48 ?? 89 75 ?? 89 01 8B 45 ?? 83 F8 
            ?? 72 ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 8D ?? ?? ?? ?? 54 E8 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 85 C0 74 
            ?? 8D 45 ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B CF 50 E8 ?? ?? ?? ?? 8B 
            45 ?? 83 F8 ?? 72 ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 
            75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 85 F6 0F 85 ?? 
            ?? ?? ?? FF 75 ?? FF 15 
        }

        $encrypt_files_p1 = {
            FF 15 ?? ?? ?? ?? 85 C0 75 ?? 50 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 
            45 ?? 83 7D ?? ?? 0F 43 45 ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 33 C0 C7 45 ?? ?? 
            ?? ?? ?? 6A ?? 50 66 89 45 ?? 8D 4D ?? 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 6A ?? 0F 
            43 45 ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 89 45 ?? FF 15 ?? ?? ?? 
            ?? 8B D8 83 FB ?? 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 53 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? 
            ?? ?? ?? 8B 4D ?? 01 0D ?? ?? ?? ?? 8B 55 ?? 11 15 ?? ?? ?? ?? 83 FA ?? 0F 8C ?? ?? 
            ?? ?? 7F ?? 85 C9 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 75 ?? 66 66 0F 1F 84 00 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 55 ?? 8B 4D ?? 68 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 
            FF 74 ?? 8B 55 ?? 8B 4D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? 
            ?? ?? 8B 55 ?? 8B 4D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 74 ?? C7 45 ?? ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 55 ?? 8D 45 ?? 8B 4D ?? 83 C4 ?? 6A
        }

        $encrypt_files_p2 = {
            50 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 53 FF 15 ?? ?? ?? ?? 
            8B 55 ?? 8B 4D ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 8D 85 
            ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? F7 D8 6A ?? 6A ?? 50 53 FF 15 ?? 
            ?? ?? ?? 8B 55 ?? 8D 45 ?? 8B 4D ?? 6A ?? 50 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 50 56 53 FF 15 ?? ?? ?? ?? 83 6D ?? ?? 0F 85 ?? ?? ?? ?? 57 E8 ?? ?? 
            ?? ?? 56 E9 ?? ?? ?? ?? 8B F1 8B C2 81 C6 ?? ?? ?? ?? 83 D0 ?? 83 F8 ?? 0F 87 ?? ?? 
            ?? ?? 72 ?? 81 FE ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 
            59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 75 ?? 66 90 
            68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 55 ?? 8B 4D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 
            0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 8B 
            55 ?? 8B 4D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            50 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 55 
            ?? 8B 4D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50
        }

        $encrypt_files_p3 = {
            E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 74 ?? C7 45 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 55 ?? 8D 45 ?? 8B 4D ?? 83 C4 ?? 6A ?? 50 E8 ?? ?? 
            ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 53 FF 15 ?? ?? ?? ?? 8B 55 ?? 8B 
            4D ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 8D 85 ?? ?? ?? ?? 
            57 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? F7 D8 6A ?? 6A ?? 50 53 FF 15 ?? ?? ?? ?? 8B 
            55 ?? 8D 45 ?? 8B 4D ?? 6A ?? 50 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 50 56 53 FF 15 ?? ?? ?? ?? 83 6D ?? ?? 0F 85 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 56 E9 
            ?? ?? ?? ?? 8B F1 8B C2 81 C6 ?? ?? ?? ?? 83 D0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 72 ?? 
            81 FE ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 75 ?? 66 90 68 ?? ?? ?? 
            ?? FF 15 ?? ?? ?? ?? 8B 55 ?? 8B 4D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 8B 55 ?? 8B 4D 
            ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 8B F0 83 C4 ?? 85 F6 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 55 ?? 8B 4D ?? 
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 8B F0 83 C4 ?? 85 F6 74 ?? C7 45 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68
        }

        $encrypt_files_p4 = { 
            50 E8 ?? ?? ?? ?? 8B 55 ?? 8D 45 ?? 8B 4D ?? 83 C4 ?? 6A ?? 50 E8 ?? ?? ?? ?? F2 0F 
            59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 57 53 FF 15 ?? ?? ?? ?? 8B 55 ?? 8B 4D ?? E8 ?? 
            ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 8D 85 ?? ?? ?? ?? 57 50 E8 ?? 
            ?? ?? ?? 8B 45 ?? 83 C4 ?? F7 D8 6A ?? 6A ?? 50 53 FF 15 ?? ?? ?? ?? 8B 55 ?? 8D 45 
            ?? 8B 4D ?? 6A ?? 50 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 56 53 
            FF 15 ?? ?? ?? ?? 83 6D ?? ?? 0F 85 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 56 E9 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 75 ?? 0F 1F 84 00 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 8B F0 83 C4 
            ?? 85 F6 74 ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 75 ?? 66 
            0F 1F 84 00 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 75 ?? E8 
            ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8D 45 ?? 6A ?? 50 FF 75 ?? 56 53 FF 15 ?? ?? ?? ?? FF 75 ?? 8D 85 ?? 
            ?? ?? ?? 57 56 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? F7 D8 6A ?? 6A ?? 50 53 FF 15 ?? 
            ?? ?? ?? 6A ?? 8D 45 ?? 50 FF 75 ?? 57 53 FF 15 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 57 E8 
            ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 0F 57 C0 66 0F 13 45 ?? 6A ?? 50 6A ?? 53 FF 15 ?? ?? 
            ?? ?? 8B 75 ?? 8D 45 ?? 6A ?? 50 FF B6 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? 
            ?? 50 FF B6 ?? ?? ?? ?? 53 FF D7 8B 35 ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 6A ?? 6A ?? 6A 
            ?? 6A ?? FF 35 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF D6 85 C0 0F 
            84 ?? ?? ?? ?? FF 75 ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? FF 35 ?? ?? ?? 
            ?? FF D6 85 C0 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 68 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 0F 1F 40 ?? 8B 45 ?? 03 C0 50 E8 ?? 
            ?? ?? ?? 8B F0 83 C4 ?? 80 3E ?? 74 ?? 8B 45 ?? 8B CE 85 C0 74 ?? 66 90 C6 01 ?? 8D 
            49 ?? 83 E8 ?? 75 ?? 8D 45 ?? 50 56 68 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? FF 15 ?? 
            ?? ?? ?? 6A ?? 8D 45 ?? 50 FF 75 ?? 56 53 FF D7 6A ?? 8D 45 ?? 50 8B 45 ?? FF B0 ?? 
            ?? ?? ?? FF 15 ?? ?? ?? ?? 50 8B 45 ?? FF B0 ?? ?? ?? ?? 53 FF D7 53 FF 15 ?? ?? ?? 
            ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 83 7D ?? ?? 0F 43 45 ?? 6A ?? 50 FF 75 ?? FF 
            15
        }

        $remote_connection = {
            FF 15 ?? ?? ?? ?? 8B F8 89 7D ?? 85 FF 0F 84 ?? ?? ?? ?? 8B 4D ?? 83 79 ?? ?? 72 ?? 
            8B 09 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 51 57 FF 15 ?? ?? ?? ?? 8B F0 89 75 ?? 85 
            F6 0F 84 ?? ?? ?? ?? 8B 4D ?? 53 83 79 ?? ?? 75 ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? 
            ?? ?? BB ?? ?? ?? ?? EB ?? 51 8D 45 ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BB 
            ?? ?? ?? ?? 6A ?? 6A ?? FF 75 ?? 8B C8 6A ?? E8 ?? ?? ?? ?? 33 C9 C7 45 ?? ?? ?? ?? 
            ?? 66 89 4D ?? 8D 4D ?? 50 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? F6 C3 ?? 74 ?? 8D 4D 
            ?? 83 E3 ?? E8 ?? ?? ?? ?? F6 C3 ?? 5B 74 ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 
            4D ?? 6A ?? 68 ?? ?? ?? ?? 51 6A ?? 68 ?? ?? ?? ?? 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 0F 
            43 45 ?? 50 68 ?? ?? ?? ?? 56 C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 85 F6 0F 
            84 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 3D ?? ?? 
            ?? ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF D7 85 C0 74 ?? 8B 45 ?? 
            85 C0 74 ?? C6 84 05 ?? ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 33 C9 EB ?? 8D 8D ?? 
            ?? ?? ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA 51 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? 
            ?? ?? ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF D7 85 C0 75 ?? 8B 7D 
            ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 8B 45 
            ?? 83 F8 ?? 72 ?? 40 8D 4D ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 83 7D 
            ?? ?? 8D 4D ?? 8B 45 ?? 8D 55 ?? 0F 43 4D ?? 8B 75 ?? 03 C1 83 7D ?? ?? 8D 4D ?? 52 
            0F 43 4D ?? 50 51 8B CE E8 ?? ?? ?? ?? 8B 4D ?? 83 F9 ?? 72 ?? 41 51 FF 75 ?? 8D 4D 
            ?? E8 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            (
                all of ($find_files_p*)
            ) and 
            (
                all of ($encrypt_files_p*)
            ) and 
            $remote_connection
        )
}
