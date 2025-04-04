rule Win32_Ransomware_Jemd : tc_detection malicious
{
    meta:
        id = "tTfeIu5LUYdZYhclnSGEL"
        fingerprint = "v1_sha256_552e0fc118031e953dee2e7c6bf8234a5a90de8c34b0e2724dfe99f2b28b8c51"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Jemd ransomware."
        category = "MALWARE"
        malware = "JEMD"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Jemd"
        tc_detection_factor = 5

    strings:

        $find_files_1 = {
            55 8B EC 81 C4 ?? ?? ?? ?? 53 33 DB 89 9D ?? ?? ?? ?? 89 4D ?? 89 55 ?? 89 45 ?? 8B 
            45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 
            64 FF 30 64 89 20 8B 45 ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 E0 ?? 83 F8 ?? 75 
            ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? 8B 
            45 ?? 50 8B 45 ?? 50 8D 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? B1 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? C3 
        }

        $find_files_2 = {
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 33 DB 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 4D ?? 
            89 55 ?? 89 45 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? 
            ?? ?? 8D B5 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? ?? ?? ?? 89 
            C3 BB ?? ?? ?? ?? 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4B 75 ?? 33 DB 8D 45 ?? 33 C9 BA 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 8A 14 1E 88 54 05 ?? 40 43 80 3C 1E ?? 74 ?? 83 F8 
            ?? 7E ?? 43 8D 85 ?? ?? ?? ?? 8D 55 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? 8B 45 ?? 50 8D 85 ?? ?? ?? ?? 8D 55 ?? B9 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? E8 ?? ?? ?? ?? 80 7C 1E 
            ?? ?? 75 ?? 80 3C 1E ?? 74 ?? 81 FB ?? ?? ?? ?? 0F 8E ?? ?? ?? ?? 33 C0 5A 59 59 64 
            89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? C3 
        }

        $encrypt_files_p1 = {
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 33 DB 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? 
            ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 8B D9 89 55 ?? 89 45 ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 
            89 20 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 80 7C 02 ?? ?? 75 ?? 8B 45 ?? E8 ?? ?? ?? ?? 
            8B D0 4A 8D 45 ?? E8 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? FF 75 ?? 8D 85 ?? ?? ?? ?? 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B D0 83 CA ?? 3B D0 75 ?? 80 
            FB ?? 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? 50 
            8B 45 ?? 50 FF 75 ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B CB 8B 55 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? FF
        }

        $encrypt_files_p2 = {
            75 ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B B5 ?? ?? ?? 
            ?? 8B C6 83 C8 ?? 3B C6 75 ?? 80 FB ?? 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? 8B 
            45 ?? 50 8B 45 ?? 50 FF 75 ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B CB 8B 55 ?? E8 ?? ?? ?? ?? EB ?? FF 
            75 ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 
            15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? C3 
        }

        $main_routine = {
            8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 
            ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? B0 ?? E8 ?? 
            ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? B2 ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 50 8D 55 ?? 66 
            B8 ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? B1 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 
            A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? FF 35 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 
            0D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B C6 8B 08 FF 51 ?? 8D 55 ?? 
            33 C0 E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B C6 8B 08 FF 
            51
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $main_routine 
        ) and 
        (
            all of ($find_files_*)
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
