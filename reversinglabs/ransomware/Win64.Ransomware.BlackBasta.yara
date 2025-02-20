rule Win64_Ransomware_BlackBasta : tc_detection malicious
{
    meta:
        id = "1h6hXT6tO36Zs9AUriJu9m"
        fingerprint = "v1_sha256_79c81a4470e9eabbd714b1a91621c7b2bbe42d5371ba2c799529662d5f5c479a"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects BlackBasta ransomware."
        category = "MALWARE"
        malware = "BLACKBASTA"
        tc_detection_type = "Ransomware"
        tc_detection_name = "BlackBasta"
        tc_detection_factor = 5

    strings:

        $find_files = {
            48 8B 44 24 ?? 83 A0 ?? ?? ?? ?? ?? 44 8B C9 EB ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 44 38
            75 ?? 74 ?? 48 8B 44 24 ?? 83 A0 ?? ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? EB ?? 44 38 75 ??
            74 ?? 48 8B 44 24 ?? 83 A0 ?? ?? ?? ?? ?? 45 8B CE 4C 8D 44 24 ?? 48 8B CF 48 8D 54
            24 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 4C 8D 45 ?? 85 C0 44 89 74 24 ?? 4C 89 74 24 ??
            49 0F 45 CE 45 33 C9 33 D2 FF 15 ?? ?? ?? ?? 48 8B D8 48 83 F8 ?? 75 ?? 4D 8B CC 45
            33 C0 33 D2 48 8B CF E8 ?? ?? ?? ?? 8B D8 44 38 74 24 ?? 74 ?? 48 8B 4C 24 ?? E8 ??
            ?? ?? ?? 8B C3 E9 ?? ?? ?? ?? 49 8B 74 24 ?? 49 2B 34 24 48 C1 FE ?? 33 D2 4C 89 75
            ?? 48 8D 4D ?? 4C 89 75 ?? 4C 89 75 ?? 4C 89 75 ?? 4C 89 75 ?? 44 88 75 ?? E8 ?? ??
            ?? ?? 48 8B 45 ?? B9 ?? ?? ?? ?? 39 48 ?? 75 ?? 44 38 75 ?? 74 ?? 48 8B 45 ?? 83 A0
            ?? ?? ?? ?? ?? 44 8B C9 EB ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 44 38 75 ?? 74 ?? 48 8B 45
            ?? 83 A0 ?? ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? EB ?? 44 38 75 ?? 74 ?? 48 8B 45 ?? 83 A0
            ?? ?? ?? ?? ?? 45 8B CE 4C 8D 44 24 ?? 48 8D 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B
            75 ?? 33 D2 85 C0 49 8B CE 48 0F 45 CA 80 39 ?? 75 ?? 8A 41 ?? 84 C0 75 ?? 38 55 ??
            74 ?? 49 8B CE E8 ?? ?? ?? ?? EB ?? 3C ?? 75 ?? 38 51 ?? 74 ?? 4D 8B CC 4D 8B C5 48
            8B D7 E8 ?? ?? ?? ?? 44 8B E8 85 C0 75 ?? 38 45 ?? 74 ?? 49 8B CE E8 ?? ?? ?? ?? 4C
            8B 6C 24 ?? 48 8D 55 ?? 48 8B CB FF 15 ?? ?? ?? ?? 45 33 F6 85 C0 0F 85 ?? ?? ?? ??
            49 8B 04 24 49 8B 54 24 ?? 48 2B D0 48 C1 FA ?? 48 3B F2 74 ?? 48 2B D6 48 8D 0C F0
            4C 8D 0D ?? ?? ?? ?? 45 8D 46 ?? E8 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 44 38 74
            24 ?? 74 ?? 48 8B 4C 24
        }

        $find_system_volumes_v1_p1 = {
            48 89 4C 24 ?? 55 53 56 57 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ??
            48 8B F1 45 33 FF 44 89 7C 24 ?? 4C 89 39 4C 89 79 ?? 4C 89 79 ?? C7 44 24 ?? ?? ??
            ?? ?? BA ?? ?? ?? ?? 48 8D 4C 24 ?? FF 15 ?? ?? ?? ?? 4C 8B F0 0F 1F 00 4C 8D 8D ??
            ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 4C 24 ?? FF 15 ?? ?? ?? ?? 85
            C0 0F 84 ?? ?? ?? ?? 44 89 7C 24 ?? 4C 89 7C 24 ?? 48 8D 85 ?? ?? ?? ?? 48 89 44 24
            ?? 4C 89 7C 24 ?? 45 33 C9 45 33 C0 33 D2 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85
            C0 0F 84 ?? ?? ?? ?? F7 85 ?? ?? ?? ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8D 8D ?? ??
            ?? ?? E8 ?? ?? ?? ?? 48 8D 14 00 48 8D BD ?? ?? ?? ?? 48 03 FA 4C 89 7C 24 ?? 4C 89
            7C 24 ?? 4C 89 7C 24 ?? 4C 89 7C 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? C6 44 24 ?? ?? 48
            8D 9D ?? ?? ?? ?? 48 D1 FA 48 83 FA ?? 72 ?? 45 33 C0 48 8D 4C 24 ?? E8
        }

        $find_system_volumes_v1_p2 = {
            4C 89 7C 24 ?? 48 8D 44 24 ?? 48 89 85 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 3B C7 74
            ?? 66 66 66 0F 1F 84 00 ?? ?? 00 00 44 0F B6 0B 48 8B 4C 24 ?? 48 8B 54 24 ?? 48 3B
            CA 73 ?? 48 8D 41 ?? 48 89 44 24 ?? 48 8D 44 24 ?? 48 83 FA ?? 48 0F 43 44 24 ?? 44
            88 0C 08 C6 44 08 ?? ?? EB ?? 45 33 C0 41 8D 50 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48
            83 C3 ?? 48 3B DF 75 ?? 4C 89 BD ?? ?? ?? ?? 48 8B 46 ?? 48 3B 46 ?? 74 ?? 4C 89 38
            4C 89 78 ?? 4C 89 78 ?? 41 B8 ?? ?? ?? ?? 48 8D 54 24 ?? 48 8B C8 E8 ?? ?? ?? ?? 4C
            89 7C 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? C6 44 24 ?? ?? 48 83 46 ?? ?? EB ?? 4C 8D 44
            24 ?? 48 8B D0 48 8B CE E8 ?? ?? ?? ?? 90 48 8B 54 24 ?? 48 83 FA ?? 72 ?? 48 FF C2
            48 8B 4C 24 ?? 48 8B C1 48 81 FA ?? ?? ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1
            48 83 C0 ?? 48 83 F8 ?? 77 ?? E8 ?? ?? ?? ?? 4C 89 7C 24 ?? 48 C7 44 24 ?? ?? ?? ??
            ?? C6 44 24 ?? ?? 41 B8 ?? ?? ?? ?? 48 8D 54 24 ?? 49 8B CE FF 15 ?? ?? ?? ?? 85 C0
            0F 85 ?? ?? ?? ?? 49 8B CE FF 15 ?? ?? ?? ?? 48 8B C6 48 81 C4
        }

        $set_default_icon_p1 = {
            48 89 5C 24 ?? 48 89 4C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ??
            48 8B F1 45 33 ED 44 89 6C 24 ?? 4C 8B 35 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ??
            ?? ?? 4C 8B F8 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 8B C8 49 2B CE 49 3B CF 0F 82 ?? ??
            ?? ?? 4C 8D 25 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? ?? 4C 0F 43 25 ?? ?? ?? ?? 4C 89 6C
            24 ?? 4C 89 6C 24 ?? 4C 89 6C 24 ?? 4B 8D 2C 37 BB ?? ?? ?? ?? 48 8D 7C 24 ?? 48 3B
            EB 0F 86 ?? ?? ?? ?? 48 8B DD 48 83 CB ?? 48 3B D8 76 ?? 48 8B D8 48 B8 ?? ?? ?? ??
            ?? ?? ?? ?? 48 8D 0C 00 EB ?? B8 ?? ?? ?? ?? 48 3B D8 48 0F 42 D8 48 8D 4B ?? 48 B8
            ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C8 0F 87 ?? ?? ?? ?? 48 03 C9 48 81 F9 ?? ?? ?? ?? 72
            ?? 48 8D 41 ?? 48 3B C1 0F 86 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 85 C0 0F 84 ??
            ?? ?? ?? 48 8D 78 ?? 48 83 E7 ?? 48 89 47 ?? EB ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48
            8B F8 EB ?? 49 8B FD 48 89 7C 24 ?? 48 89 6C 24 ?? 48 89 5C 24 ?? 4B 8D 1C 36 4C 8B
        }

        $set_default_icon_p2 = {
            C3 49 8B D4 48 8B CF E8 ?? ?? ?? ?? 48 8D 0C 3B 4F 8D 04 3F 48 8D 15 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 66 44 89 2C 6F BB ?? ?? ?? ?? 89 5C 24 ?? 48 8D 54 24 ?? 48 83 7C 24 ??
            ?? 48 0F 43 54 24 ?? 48 8D 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 84 24 ?? ?? ?? ??
            48 89 44 24 ?? 4C 89 6C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 44 89 6C 24 ?? 45 33 C9 45 33
            C0 48 C7 C1 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 48 8B CE 48 83 7E ?? ?? 72 ??
            48 8B 0E 8B 46 ?? 03 C0 89 44 24 ?? 48 89 4C 24 ?? 44 8B CB 45 33 C0 48 8D 15 ?? ??
            ?? ?? 48 8B 8C 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 45 33 C9 45 33 C0 33 D2 B9 ?? ?? ??
            ?? FF 15 ?? ?? ?? ?? 45 33 C9 45 33 C0 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? FF 15 ?? ?? ??
            ?? EB ?? 4C 89 6C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? 48 89 4C 24
            ?? 45 33 C9 44 8B C0 33 D2 B9 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 E3 ?? 89 5C 24 ?? 48
            8B 54 24 ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8B C1 48 81
            FA ?? ?? ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1 48 83 C0 ?? 48 83 F8 ?? 77 ??
            E8 ?? ?? ?? ?? 4C 89 6C 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? 66 44 89 6C 24 ?? 48 8B CE
            E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 41 5F 41 5E 41 5D 41 5C
            5F 5E 5D C3
        }

        $cmd_prompt = {
            48 89 5C 24 ?? 48 89 7C 24 ?? 55 48 8B EC 48 83 EC ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4
            48 89 45 ?? 48 8B D9 4C 8D 05 ?? ?? ?? ?? 33 FF 48 8D 4D ?? 33 D2 48 89 7D ?? E8 ??
            ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 48 85 DB 75 ?? 48 8B 4D ?? 48 85 C9 0F 84 ?? ??
            ?? ?? 33 D2 E8 ?? ?? ?? ?? 48 8B 4D ?? 8B D8 E8 ?? ?? ?? ?? 85 DB 40 0F 94 C7 E9 ??
            ?? ?? ?? 48 8B 45 ?? 48 8D 0D ?? ?? ?? ?? 48 89 45 ?? 48 89 4D ?? 48 89 5D ?? 48 89
            7D ?? 48 85 C0 74 ?? E8 ?? ?? ?? ?? 8B 18 E8 ?? ?? ?? ?? 45 33 C9 4C 8D 45 ?? 33 C9
            89 38 48 8B 55 ?? E8 ?? ?? ?? ?? 48 8B F8 83 F8 ?? 74 ?? E8 ?? ?? ?? ?? 89 18 EB ??
            E8 ?? ?? ?? ?? 83 38 ?? 74 ?? E8 ?? ?? ?? ?? 83 38 ?? 74 ?? 48 8B 4D ?? E8 ?? ?? ??
            ?? 83 CF ?? EB ?? E8 ?? ?? ?? ?? 89 18 48 8D 15 ?? ?? ?? ?? 45 33 C9 4C 8D 45 ?? 48
            89 55 ?? 33 C9 E8 ?? ?? ?? ?? 48 8B F8 48 8B 4D ?? E8 ?? ?? ?? ?? 8B C7 48 8B 4D ??
            48 33 CC E8 ?? ?? ?? ?? 4C 8D 5C 24 ?? 49 8B 5B ?? 49 8B 7B ?? 49 8B E3 5D C3
        }

        $exclude_from_encryption = {
            66 89 75 ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B C0 48 8D 15 ?? ?? ?? ?? 48 8D
            4D ?? E8 ?? ?? ?? ?? 90 45 33 C0 48 8D 55 ?? 48 8B CB E8 ?? ?? ?? ?? 48 8B F8 48 8B
            55 ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 8B 4D ?? 48 8B C1 48 81 FA ?? ??
            ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1 48 83 C0 ?? 48 83 F8 ?? 0F 87 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 48 89 75 ?? 48 C7 45 ?? ?? ?? ?? ?? 66 89 75 ?? 48 83 FF ?? 0F 85
            ?? ?? ?? ?? 48 89 75 ?? 48 89 75 ?? 48 89 75 ?? 48 89 75 ?? 48 C7 45 ?? ?? ?? ?? ??
            66 89 75 ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B C0 48 8D 15 ?? ?? ?? ?? 48 8D
            4D ?? E8 ?? ?? ?? ?? 90 45 33 C0 48 8D 55 ?? 48 8B CB E8 ?? ?? ?? ?? 48 8B F8 48 8B
            55 ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 8B 4D ?? 48 8B C1 48 81 FA ?? ??
            ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1 48 83 C0 ?? 48 83 F8 ?? 0F 87 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 48 89 75 ?? 48 C7 45 ?? ?? ?? ?? ?? 66 89 75 ?? 48 83 FF ?? 0F 85
            ?? ?? ?? ?? 48 89 75 ?? 48 89 75 ?? 48 89 75 ?? 48 89 75 ?? 48 C7 45 ?? ?? ?? ?? ??
            66 89 75 ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B C0 48 8D 15 ?? ?? ?? ?? 48 8D
            4D ?? E8 ?? ?? ?? ?? 90 45 33 C0 48 8D 55 ?? 48 8B CB E8 ?? ?? ?? ?? 48 8B F8 48 8B
            55 ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 8B 4D ?? 48 8B C1 48 81 FA ?? ??
            ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1 48 83 C0
        }

        $encrypt_files_v1 = {
            41 83 CC ?? 44 89 64 24 ?? 48 8D 8C 24 ?? ?? ?? ?? 48 83 FF ?? 48 0F 43 8C 24 ?? ??
            ?? ?? FF 15 ?? ?? ?? ?? 8B F8 41 83 E4 ?? 44 89 64 24 ?? 48 8B 94 24 ?? ?? ?? ?? 48
            83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 8B 8C 24 ?? ?? ??
            ?? 48 8B C1 48 81 FA ?? ?? ?? ?? 72 ?? 48 83 C2 ?? 48 89 94 24 ?? ?? ?? ?? 48 8B 49
            ?? 48 2B C1 48 83 C0 ?? 48 83 F8 ?? 0F 87 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 9C 24 ??
            ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 9C 24 ?? ?? 00 00 40 F6 C7 ?? 74
            ?? 49 8B CF E8 ?? ?? ?? ?? 90 48 BE ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 3D ?? ?? ?? ?? 4C
            8D 35 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? E9 ?? ?? ?? ?? 49 8B CF E8 ?? ?? ?? ?? C6 84
            24 ?? ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B F0 48
            89 9C 24 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 4C 8B 70 ?? 48
            83 78 ?? ?? 72 ?? 48 8B 30 48 8D 8C 24 ?? ?? ?? ?? 49 83 FE ?? 73 ?? 41 B8 ?? ?? ??
            ?? 48 8B D6 E8 ?? ?? ?? ?? 4C 89 B4 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ??
            ?? EB ?? 4C 89 AC 24 ?? ?? ?? ?? 49 8B FE 48 83 CF ?? 48 89 BC 24 ?? ?? ?? ?? 49 3B
            FD 49 0F 47 FD 48 8D 57 ?? E8 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 4E 8D 04 75 ?? ??
            ?? ?? 48 8B D6 48 8B C8 E8 ?? ?? ?? ?? 4C 89 B4 24 ?? ?? ?? ?? 48 89 BC 24
        }

        $find_system_volumes_v2 = {
            BA ?? ?? ?? ?? 48 8D 4C 24 ?? FF 15 ?? ?? ?? ?? 48 8B F8 0F 1F 44 00 ?? 4C 8D 8D ??
            ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 4C 24 ?? FF 15 ?? ?? ?? ?? 85
            C0 0F 84 ?? ?? ?? ?? 89 74 24 ?? 48 89 74 24 ?? 48 8D 85 ?? ?? ?? ?? 48 89 44 24 ??
            48 89 74 24 ?? 45 33 C9 45 33 C0 33 D2 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0
            0F 84 ?? ?? ?? ?? F7 85 ?? ?? ?? ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8D 8D ?? ?? ??
            ?? E8 ?? ?? ?? ?? 4C 8D 04 00 48 8D 85 ?? ?? ?? ?? 49 03 C0 48 89 74 24 ?? 48 89 74
            24 ?? 48 89 74 24 ?? 48 89 74 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? 66 89 74 24 ?? 48 8D
            8D ?? ?? ?? ?? 48 3B C8 74 ?? 49 D1 F8 48 8D 95 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ??
            ?? ?? 90 48 8B 43 ?? 48 3B 43 ?? 74 ?? 48 89 30 48 89 70 ?? 48 89 70 ?? 41 B8 ?? ??
            ?? ?? 48 8D 54 24 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 89 74 24 ?? 48 C7 44 24 ?? ?? ?? ??
            ?? 66 89 74 24 ?? 48 83 43 ?? ?? EB ?? 4C 8D 44 24 ?? 48 8B D0 48 8B CB E8 ?? ?? ??
            ?? 90 48 8B 54 24 ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8B
            C1 48 81 FA ?? ?? ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1 48 83 C0 ?? 48 83 F8
            ?? 77 ?? E8 ?? ?? ?? ?? 48 89 74 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? 66 89 74 24 ?? 41
            B8 ?? ?? ?? ?? 48 8D 54 24 ?? 48 8B CF FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48
            8B CF FF 15 ?? ?? ?? ?? 48 8B C3 48 8B 9C 24 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5F 5E
            5D C3
        }

        $drop_ransom_note = {
            48 83 3D ?? ?? ?? ?? ?? 48 0F 43 15 ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 48 8D 4D ?? E8
            ?? ?? ?? ?? 48 8B D8 4C 89 75 ?? 4C 89 75 ?? 4C 89 75 ?? 45 8D 46 ?? 48 8B D0 48 8D
            4D ?? E8 ?? ?? ?? ?? 4C 89 73 ?? 48 C7 43 ?? ?? ?? ?? ?? 66 44 89 33 BE ?? ?? ?? ??
            89 75 ?? 83 E6 ?? 89 75 ?? 48 8B 55 ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48
            8B 4D ?? 48 8B C1 48 81 FA ?? ?? ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1 48 83
            C0 ?? 48 83 F8 ?? 0F 87 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 75 ?? 48 C7 45 ?? ?? ?? ??
            ?? 66 44 89 75 ?? 48 8D 4D ?? 48 83 7D ?? ?? 48 0F 43 4D ?? 4C 89 74 24 ?? C7 44 24
            ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 45 33 C9 45 33 C0 BA ?? ?? ?? ?? FF 15 ?? ??
            ?? ?? 48 8B D8 48 83 F8 ?? 74 ?? 4C 89 74 24 ?? 45 33 C9 41 B8 ?? ?? ?? ?? 48 8D 15
            ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 83 E6 ?? 89 75 ??
            48 8B 55 ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 8B 4D ?? 48 8B C1 48 81 FA
            ?? ?? ?? ?? 72 ?? 48 83 C2 ?? 48 8B 49 ?? 48 2B C1 48 83 C0 ?? 48 83 F8 ?? 0F 87 ??
            ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 75 ?? 48 C7 45 ?? ?? ?? ?? ?? 66 44 89 75 ?? 48 8B 57
            ?? 48 83 FA ?? 72 ?? 48 8D 14 55 ?? ?? ?? ?? 48 8B 0F 48 81 FA ?? ?? ?? ?? 72 ?? 48
            83 C2 ?? 4C 8B 41 ?? 49 2B C8 48 8D 41 ?? 48 83 F8 ?? 77 ?? 49 8B C8 E8 ?? ?? ?? ??
            4C 89 77 ?? 48 C7 47 ?? ?? ?? ?? ?? 66 44 89 37 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 5B ??
            49 8B 73 ?? 49 8B 7B
        }

        $encrypt_files_v2_p1 = {
            BA ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B D8 48 83 F8 ?? 75 ?? 48 8D 8D ?? ?? ?? ?? E8
            ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89
            85 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 49 8B FA 49 8B D1 4D 85 D2
            74 ?? 4C 8B C1 4D 2B C1 0F B7 02 66 41 39 04 10 75 ?? 48 83 C2 ?? 48 83 EF ?? 75 ??
            49 2B CB 48 D1 F9 E9 ?? ?? ?? ?? 48 83 C1 ?? E9 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48
            8B CB FF 15 ?? ?? ?? ?? 85 C0 75 ?? 48 8B CB FF 15 ?? ?? ?? ?? 90 48 8D 8D ?? ?? ??
            ?? E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ??
            48 89 85 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 8B BD ?? ?? ?? ?? B2 ?? 48 8D 4C 24 ?? E8 ??
            ?? ?? ?? B2 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 0B 00 F3 0F 7F 45 ??
            48 89 75 ?? 48 89 75 ?? 48 8D 45 ?? 48 89 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 44 24 ??
            C6 45 ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 ?? 48 C7 45 ?? ?? ?? ?? ?? C6 45
            ?? ?? 48 8D 45 ?? 83 E0 ?? 48 8D 44 05 ?? 48 89 45 ?? 89 75 ?? C7 45 ?? ?? ?? ?? ??
            48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 05 ??
            ?? ?? ?? 48 89 44 24 ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89
            44 24 ?? 48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 48
            8D 05 ?? ?? ?? ?? 48 89 45 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48
            C7 44 24 ?? ?? ?? ?? ?? 48 C7 44 24 ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C
            8B E8 48 89 44 24 ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ??
            ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B F8 48 89 85 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 49
        }

        $encrypt_files_v2_p2 = {
            8B D5 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 8B D7 48 8D 0D ?? ??
            ?? ?? E8 ?? ?? ?? ?? 48 C7 44 24 ?? ?? ?? ?? ?? 4C 8B CF 41 B8 ?? ?? ?? ?? 49 8B D5
            48 8D 4C 24 ?? E8 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 49 8B D5 48 8B 8D ?? ?? ?? ?? E8 ??
            ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 83 C1 ?? 41 B8 ?? ?? ?? ?? 48 8B D7 E8 ?? ?? ?? ??
            BF ?? ?? ?? ?? 4C 3B FF 0F 8D ?? ?? ?? ?? F2 0F 10 35 ?? ?? ?? ?? 48 8B FE 49 8B C7
            48 2B C7 48 99 83 E2 ?? 48 03 C2 48 C1 F8 ?? 4C 8B F0 F2 0F 59 35 ?? ?? ?? ?? 0F 57
            C0 F2 48 0F 2A C0 F2 0F 59 F0 F2 48 0F 2C CE 48 85 C9 0F 85 ?? ?? ?? ?? 4D 85 FF 0F
            8E ?? ?? ?? ?? 48 8D 45 ?? 48 89 44 24 ?? 48 8D 54 24 ?? 48 8D 4D ?? E8 ?? ?? ?? ??
            90 48 8D 35 ?? ?? ?? ?? 48 89 75 ?? 4C 8D 35 ?? ?? ?? ?? 4C 89 75 ?? 48 8D 05 ?? ??
            ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 44 24
            ?? 4D 8B CF 45 33 C0 48 8B D3 48 8B 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 49
            81 FF ?? ?? ?? ?? 0F 8E ?? ?? ?? ?? F2 0F 10 35 ?? ?? ?? ?? 48 8D 45 ?? 48 89 44 24
            ?? 48 8D 54 24 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48
            8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ??
            48 89 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 44 24 ?? 4C 8B CF 45 33 C0 48 8B D3 49 8B CE
            E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 99 48 F7 F9 4C 8B E8 48 85 C0 75 ?? 48 8D 45 ?? 48
        }

        $encrypt_files_v2_p3 = {
            89 44 24 ?? 48 8D 54 24 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 35 ?? ?? ?? ?? 48 89
            75 ?? 4C 8D 35 ?? ?? ?? ?? 4C 89 75 ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ??
            ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 44 24 ?? 4D 8B CF 45 33 C0 48 8B D3
            48 8B 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B 6C 24 ?? E9 ?? ?? ?? ?? 4D 85 F6 0F 8E ??
            ?? ?? ?? 4D 8B FD 49 C1 E7 ?? 4C 8B A5 ?? ?? ?? ?? 90 48 8D 45 ?? 48 89 44 24 ?? 48
            8D 54 24 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05
            ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8D 05 ?? ?? ?? ?? 48 89
            85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 44 24 ?? 41 B9 ?? ?? ?? ?? 4C 8B C7 48 8B D3 49 8B
            CC E8 ?? ?? ?? ?? 49 03 F5 49 03 FF 49 3B F6 7C ?? 4C 8B A5 ?? ?? ?? ?? 4C 8B 6C 24
            ?? 48 8D 35 ?? ?? ?? ?? 4C 8D 35 ?? ?? ?? ?? 4C 8D 8D ?? ?? ?? ?? 4C 8B C3 48 8B 95
            ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 4D 8B C4
            48 8D 95 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8B 95 ?? ?? ?? ?? 48
            85 D2 74 ?? 48 8B FA 33 C0 B9 ?? ?? ?? ?? F3 AA 48 8B CA E8 ?? ?? ?? ?? 90 4D 85 ED
            74 ?? 49 8B FD 33 C0 B9 ?? ?? ?? ?? F3 AA 49 8B CD E8 ?? ?? ?? ?? 90 48 89 74 24 ??
            4C 89 74 24
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            (
                (
                    $find_files
                ) and
                (
                    all of ($find_system_volumes_v1_p*)
                ) and
                (
                    all of ($set_default_icon_p*)
                ) and
                (
                    $cmd_prompt
                ) and
                (
                    $exclude_from_encryption
                ) and
                (
                    $encrypt_files_v1
                )
            ) or
            (
                (
                    $find_files
                ) and
                (
                    $cmd_prompt
                ) and
                (
                    $find_system_volumes_v2
                ) and
                (
                    $drop_ransom_note
                ) and
                (
                    all of ($encrypt_files_v2_p*)
                )
            )
        )
}
