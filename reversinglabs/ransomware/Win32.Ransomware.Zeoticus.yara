rule Win32_Ransomware_Zeoticus : tc_detection malicious
{
    meta:
        id = "2QbAmYROVhTBe6ijMFPx4N"
        fingerprint = "v1_sha256_adf42b96139ad98f4253f3eba2c4af1be9545825605e0851185cc15284d9e9a0"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Zeoticus ransomware."
        category = "MALWARE"
        malware = "ZEOTICUS"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Zeoticus"
        tc_detection_factor = 5

    strings:

        $enum_shares_p1 = {
            53 55 8B 2D ?? ?? ?? ?? 8B C1 56 57 8B 3D ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 4C 24 ?? 51 8D 4C 24 ?? 51 
            8D 4C 24 ?? 51 6A ?? 8D 4C 24 ?? 51 6A ?? 50 FF 15 ?? ?? ?? ?? 89 44 24 ?? 85 C0 74 
            ?? 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 83 7C 24 ?? ?? 8B 5C 24 ?? 89 5C 24 ?? C7 44 24 
            ?? ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? 33 F6 39 73 ?? 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 
            33 FF D5 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 33 FF D5 85 C0 0F 84 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? FF 33 FF D5 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 33 FF D5 85 C0 
            0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 33 FF D5 85 C0 0F 84 ?? ?? ?? ?? FF 33 8D 44 24 
            ?? FF 74 24 ?? 68 ?? ?? ?? ?? 50 FF D7 A1 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 68 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 83 C4 ?? 89 04 8D ?? ?? ?? ?? 8D 4C 24 ?? 51
        }

        $enum_shares_p2 = {
            50 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8D 04 85 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 56 FF 34 
            85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 56 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 04 8D ?? 
            ?? ?? ?? 41 FF 05 ?? ?? ?? ?? 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 FF 85 C0 7E ?? 8D 
            5F ?? 8D 44 24 ?? 50 FF 34 BD ?? ?? ?? ?? FF D5 85 C0 0F 44 F3 47 3B 3D ?? ?? ?? ?? 
            7C ?? 8B 5C 24 ?? 85 F6 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? 
            ?? ?? 8B 3D ?? ?? ?? ?? 89 04 8D ?? ?? ?? ?? 8D 4C 24 ?? 51 68 ?? ?? ?? ?? 50 FF D7 
            A1 ?? ?? ?? ?? 83 C4 ?? 8D 04 85 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 6A ?? FF 34 85 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 04 8D ?? ?? 
            ?? ?? 41 FF 05 ?? ?? ?? ?? 89 0D ?? ?? ?? ?? EB ?? 8B 3D ?? ?? ?? ?? 8B 74 24 ?? 83 
            C3 ?? 46 89 5C 24 ?? 89 74 24 ?? 3B 74 24 ?? 0F 82 ?? ?? ?? ?? 8B 5C 24 ?? 53 FF 15 
            ?? ?? ?? ?? 81 7C 24 ?? ?? ?? ?? ?? 8B 44 24 ?? 0F 84 ?? ?? ?? ?? 5F 5E 5D 5B 81 C4 
            ?? ?? ?? ?? C3 
        }

        $encrypt_files = {
            68 ?? ?? ?? ?? 6A ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? A3 ?? ?? 
            ?? ?? FF D0 68 ?? ?? ?? ?? 6A ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F0 E8 ?? ?? ?? ?? 
            83 C4 ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 FF D0 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF D7 83 
            C4 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 
            04 45 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 
            FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F0 83 FB ?? 75 ?? E8 ?? ?? ?? ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB ?? 83 FB ?? 75 ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 
            56 6A ?? FF 35 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D6 E8 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? FF B4 24 ?? ?? ?? ?? 51 E8 ?? ?? ?? 
            ?? 83 C4 ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8
        }

        $find_files = {
            81 EC ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 68 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? 8D 51 ?? 66 8B 01 
            83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 66 83 7C 24 ?? ?? 56 8D 71 ?? 0F 85 ?? ?? ?? ?? 
            55 8B 2D ?? ?? ?? ?? 57 8B 3D ?? ?? ?? ?? 66 90 66 83 7C 24 ?? ?? 0F 85 ?? ?? ?? ?? 
            66 83 7C 24 ?? ?? 0F 85 ?? ?? ?? ?? 66 83 7C 24 ?? ?? 0F 85 ?? ?? ?? ?? 66 83 7C 74 
            ?? ?? 0F 85 ?? ?? ?? ?? 33 C0 66 89 44 74 ?? 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 
            8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 66 89 4C 74 ?? 85 C0 74 ?? 33 F6 90 
            FF 34 B5 ?? ?? ?? ?? FF D7 83 F8 ?? 74 ?? 46 83 FE ?? 72 ?? 8D 44 24 ?? 50 FF 34 B5 
            ?? ?? ?? ?? FF D5 68 ?? ?? ?? ?? 8D 44 24 ?? 50 53 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8D 
            4C 24 ?? 8D 51 ?? 66 90 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 66 83 7C 24 ?? 
            ?? 8D 71 ?? 0F 84 ?? ?? ?? ?? 5F 5D 53 FF 15 ?? ?? ?? ?? 5E 5B 81 C4 ?? ?? ?? ?? C3 
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            $encrypt_files
        ) and
        (
            all of ($enum_shares_p*)
        )
}
