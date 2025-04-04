rule Win32_Ransomware_BlueLocker : tc_detection malicious
{
    meta:
        id = "qghPA0CY6tKBnsFoPEV7v"
        fingerprint = "v1_sha256_fbe5f246f4554e63b5da6a0aca169e8221a84fce18fd437ae7ad9b068e9ca576"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects BlueLocker ransomware."
        category = "MALWARE"
        malware = "BLUELOCKER"
        tc_detection_type = "Ransomware"
        tc_detection_name = "BlueLocker"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 8B 45 ?? 53 56 8B 75 ?? 57
            8B 7D ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 56 89 55 ?? 89 75 ??
            89 45 ?? 89 7D ?? FF 15 ?? ?? ?? ?? 8B D8 C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 50 53 FF 15
            ?? ?? ?? ?? 8B 55 ?? 33 C9 0B C8 89 55 ?? 89 4D ?? 83 FB ?? 75 ?? 0B C3 5F 5E 5B 8B
            4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 6A ?? 56 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B
            F0 FF 15 ?? ?? ?? ?? 33 C9 03 F0 83 C6 ?? 0F 92 C1 F7 D9 0B CE 51 E8 ?? ?? ?? ?? 8B
            F0 83 C4 ?? 89 75 ?? 85 F6 0F 84 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 50 FF 75 ??
            56 E8 ?? ?? ?? ?? 83 C4 ?? D1 E8 50 56 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 E8
            ?? ?? ?? ?? 83 C4 ?? D1 E8 50 56 E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? 85 C9 0F 8C ?? ??
            ?? ?? 8B 45 ?? 0F 8F ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? 85 C9 0F 8F ?? ??
            ?? ?? 7C ?? 3D ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? 6A ?? 53 FF 15 ?? ?? ?? ?? 8B 55 ?? 8D
            4D ?? D1 E8 89 45 ?? E8 ?? ?? ?? ?? 0F B6 4F ?? 0F 57 C0 0F B6 47 ?? C1 E1 ?? 0B C8
        }

        $encrypt_files_p2 = {
            66 0F 13 45 ?? 0F B6 47 ?? C1 E1 ?? 0B C8 C7 45 ?? ?? ?? ?? ?? 0F B6 07 C1 E1 ?? 0B
            C8 C7 45 ?? ?? ?? ?? ?? 0F B6 47 ?? 89 4D ?? 0F B6 4F ?? C1 E1 ?? 0B C8 0F B6 47 ??
            6A ?? 6A ?? FF 75 ?? C1 E1 ?? FF 75 ?? 0B C8 0F B6 47 ?? 8B 3D ?? ?? ?? ?? C1 E1 ??
            0B C8 53 89 4D ?? FF D7 33 F6 8D 45 ?? 56 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 15
            ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 0F 1F 40 ?? FF 75 ?? BA ?? ?? ?? ?? 8D 4D ?? E8
            ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? 33 C0 F7 D9 13 C0 6A ?? 6A ?? F7 D8 50 51 53 FF D7 6A
            ?? 8D 45 ?? 50 FF 75 ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ??
            8B 45 ?? 03 F0 3B 75 ?? 0F 87 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? 6A ?? 8D
            45 ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 85 C0 75 ?? E9 ?? ?? ??
            ?? 85 C9 7F ?? 7C ?? 3D ?? ?? ?? ?? 73 ?? 8B 75 ?? 8B CB 57 8B D6 E8 ?? ?? ?? ?? 8B
            3D ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 8B 75 ?? 8B CB 57 8B D6 E8 ?? ?? ?? ?? 8B 3D
            ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 8B 55 ?? 8D 4D ?? E8 ?? ?? ?? ?? 0F B6 4F ?? 0F
        }

        $encrypt_files_p3 = {
            57 C0 0F B6 47 ?? C1 E1 ?? 0B C8 66 0F 13 45 ?? 0F B6 47 ?? C1 E1 ?? 0B C8 C7 45 ??
            ?? ?? ?? ?? 0F B6 07 C1 E1 ?? 0B C8 C7 45 ?? ?? ?? ?? ?? 0F B6 47 ?? 89 4D ?? 0F B6
            4F ?? C1 E1 ?? 0B C8 0F B6 47 ?? 6A ?? 6A ?? FF 75 ?? C1 E1 ?? FF 75 ?? 0B C8 0F B6
            47 ?? 8B 3D ?? ?? ?? ?? C1 E1 ?? 0B C8 53 89 4D ?? FF D7 8B 35 ?? ?? ?? ?? 8D 45 ??
            6A ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF D6 85 C0 74 ?? FF 75 ?? BA ?? ?? ?? ??
            8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? 33 C0 F7 D9 13 C0 6A ?? 6A ?? F7 D8 50 51
            53 FF D7 6A ?? 8D 45 ?? 50 FF 75 ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 85 C0 74 ??
            81 7D ?? ?? ?? ?? ?? 72 ?? 6A ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF D6
            85 C0 75 ?? 8B 75 ?? 6A ?? 0F 57 C0 6A ?? 66 0F 13 45 ?? FF 75 ?? FF 75 ?? 53 FF D7
            6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D0 C7 45 ?? ?? ?? ?? ?? 83 C4 ?? 89 55 ?? C7
            45 ?? ?? ?? ?? ?? 85 D2 74 ?? 8B FA B9 ?? ?? ?? ?? F3 A5 8B 4D ?? 68 ?? ?? ?? ?? 8B
            01 8B 49 ?? 89 82 ?? ?? ?? ?? 8D 45 ?? 50 52 6A ?? 6A ?? 6A ?? FF 75 ?? 89 8A ?? ??
            ?? ?? FF 15 ?? ?? ?? ?? 8B 75 ?? 85 C0 74 ?? 6A ?? 8D 45 ?? 50 FF 75 ?? 56 53 FF 15
            ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 33 F6 EB ?? 83 CE ?? 85 DB 74 ?? 53 FF 15 ??
            ?? ?? ?? 8B 7D ?? 57 FF 75 ?? FF 15 ?? ?? ?? ?? EB ?? 8B 7D ?? 57 E8 ?? ?? ?? ?? 8B
            4D ?? 83 C4 ?? 8B C6 33 CD 5F 5E 5B E8 ?? ?? ?? ?? 8B E5 5D C3
        }

        $find_files_p1 = {
            FF 74 B4 ?? 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 46 83
            FE ?? 7C ?? FF 74 24 ?? FF D7 68 ?? ?? ?? ?? 8B F0 FF D7 03 F0 8D 84 24 ?? ?? ?? ??
            6A ?? 50 FF D7 8D 0C 06 33 C0 83 C1 ?? 0F 92 C0 F7 D8 0B C1 50 E8 ?? ?? ?? ?? 8B F0
            83 C4 ?? 85 F6 0F 84 ?? ?? ?? ?? FF 74 24 ?? FF D7 48 50 FF 74 24 ?? 56 E8 ?? ?? ??
            ?? 83 C4 ?? D1 E8 50 56 E8 ?? ?? ?? ?? 83 C4 ?? 8D 84 24 ?? ?? ?? ?? 50 56 E8 ?? ??
            ?? ?? 83 C4 ?? D1 E8 50 56 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ??
            83 C4 ?? D1 E8 50 56 E8 ?? ?? ?? ?? 8B 7C 24 ?? 83 C4 ?? 83 C7 ?? 57 FF 15 ?? ?? ??
            ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 8B C8 83 C4 ?? 85 C9 74 ?? 8B 54 24 ?? C7 01 ?? ?? ??
            ?? C7 41 ?? ?? ?? ?? ?? 83 7A ?? ?? 75 ?? 89 4A ?? 89 4A ?? 57 89 31 FF 15 ?? ?? ??
            ?? E9 ?? ?? ?? ?? 8B 42 ?? 89 48 ?? 8B 42 ?? 8B 40 ?? 89 42 ?? 89 30 57 FF 15 ?? ??
            ?? ?? E9 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 33 F6 C7 44 24 ?? ?? ?? ?? ?? C7 44 24
            ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24
            ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24
            ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF 74 B4 ?? 8D 84 24
        }

        $find_files_p2 = {
            50 FF D3 85 C0 0F 85 ?? ?? ?? ?? 46 83 FE ?? 7C ?? 6A ?? FF 74 24 ?? FF D7 8B F0 8D
            84 24 ?? ?? ?? ?? 50 FF D7 03 F0 33 C0 83 C6 ?? 0F 92 C0 F7 D8 0B C6 50 E8 ?? ?? ??
            ?? 8B F0 83 C4 ?? 85 F6 0F 84 ?? ?? ?? ?? FF 74 24 ?? FF D7 48 50 FF 74 24 ?? 56 E8
            ?? ?? ?? ?? 83 C4 ?? D1 E8 50 56 E8 ?? ?? ?? ?? 83 C4 ?? 8D 84 24 ?? ?? ?? ?? 50 56
            E8 ?? ?? ?? ?? 83 C4 ?? D1 E8 50 56 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 68 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 75 ?? 56 E8 ?? ?? ?? ?? EB ?? 6A ?? 6A ?? E8 ?? ??
            ?? ?? 8B D8 83 C4 ?? 85 DB 75 ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 57 EB ?? 57 68 ?? ?? ??
            ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 53 6A ?? FF 74 24 ?? FF 15 ?? ?? ?? ??
            85 C0 74 ?? 8B 54 24 ?? 53 57 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 E8 ?? ?? ?? ?? 83 C4 ??
            57 E8 ?? ?? ?? ?? 83 C4 ?? 53 E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 ?? 8B 35 ?? ??
            ?? ?? 8D 84 24 ?? ?? ?? ?? 50 FF 74 24 ?? FF 15
        }

        $create_crypt_context = {
            55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ??
            ?? ?? ?? 6A ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 83 C8 ?? 8B 4D ?? 33 CD E8 ?? ?? ??
            ?? 8B E5 5D C2 ?? ?? 56 8B 35 ?? ?? ?? ?? 8D 45 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ??
            ?? 6A ?? 50 FF D6 85 C0 75 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 50 8D 45 ?? 50 FF
            D6 85 C0 75 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 50 8D 45 ?? 50 FF D6 85 C0 75 ??
            68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 50 8D 45 ?? 50 FF D6 85 C0 0F 84 ?? ?? ?? ?? 6A
            ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 74 ?? 68 ?? ?? ?? ?? 56 6A ??
            FF 15 ?? ?? ?? ?? 8D 45 ?? 89 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ??
            68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D
            04 45 ?? ?? ?? ?? 50 FF 35 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 75 ?? FF 15 ??
            ?? ?? ?? 85 C0 75 ?? 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ??
            ?? ?? ?? 8B 45 ?? 5E 85 C0 74 ?? 6A ?? 50 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ??
            33 C0 33 CD E8 ?? ?? ?? ?? 8B E5 5D C2
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            $create_crypt_context
        ) and
        (
            all of ($encrypt_files_p*)
        )
}
