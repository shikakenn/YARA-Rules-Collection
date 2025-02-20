rule Win32_Ransomware_Saturn : tc_detection malicious
{
    meta:
        id = "n2VWmBmZTkWIbWQO98TbI"
        fingerprint = "v1_sha256_efa748346ad8c46e654542d302e81d633a2d12f421636c477431a12a34636132"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Saturn ransomware."
        category = "MALWARE"
        malware = "SATURN"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Saturn"
        tc_detection_factor = 5

    strings:

        $find_files_1 = {
            6A ?? C6 45 ?? ?? 8D 4D ?? 8B 3B 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? 3B C8 74 ?? 
            83 78 ?? ?? 8B C8 72 ?? 8B 08 FF 70 ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 
            85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 
            ?? ?? 8D 4D ?? 6A ?? 68 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 
            ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? 6A ?? 68 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 6A
        }

        $find_files_2_p1 = {
            68 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? FF B5 
            ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 8D 4D ?? 83 7D ?? ?? 8B 55 ?? 0F 43 4D ?? 50 51 E8 
            ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8D 85 ?? ?? ?? ?? FF 75 
            ?? 0F 43 85 ?? ?? ?? ?? 8D 4D ?? 83 7D ?? ?? 8B 55 ?? 0F 43 4D ?? 50 51 E8 ?? ?? ?? 
            ?? 83 C4 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? FF 75 ?? 0F 43 45 ?? 8D 
            4D ?? 83 7D ?? ?? 8B 55 ?? 0F 43 4D ?? 50 51 E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 85 
            ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? FF 75 ?? 0F 43 45 ?? 8D 4D ?? 83 7D ?? ?? 8B 55 ?? 
            0F 43 4D ?? 50 51 E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 51 8D 85 ?? ?? 
            ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 51 8D 85 ?? ?? ?? ?? 50 
            8D 4D ?? E8 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 51 8D 85 ?? ?? ?? ?? 50 8D 4D ?? 
            E8 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 51 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? 
            ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 51 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 83
        }

        $find_files_2_p2 = { 
            F8 ?? 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8D 8D ?? ?? ?? ?? 8D 45 ?? 0F 43 45 ?? 51 50 FF 
            15 ?? ?? ?? ?? 8B D8 89 9D ?? ?? ?? ?? 83 FB ?? 0F 84 ?? ?? ?? ?? 8B 5D ?? 8B F0 80 
            BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? FF B5 ?? 
            ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 00 
            ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B D0 
            8D 71 ?? 8A 01 41 84 C0 75 ?? 2B CE 8D 85 ?? ?? ?? ?? 51 50 8B CA E8 ?? ?? ?? ?? F6 
            85 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 84 DB 0F 84 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 95 
            ?? ?? ?? ?? 53 FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 0F 84 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C6 E9
        }

        $encrypt_files_p1 = {
            6A ?? 68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 89 9D ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 6A ?? FF B5 
            ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 
            6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 56 8B 35 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF D6 8B D8 
            83 FB ?? 0F 84 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 57 
            FF D6 89 85 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? 
            ?? ?? B9 ?? ?? ?? ?? 50 6A ?? 8D 85 ?? ?? ?? ?? BE ?? ?? ?? ?? 8D BD ?? ?? ?? ?? F3 
            A5 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 
            FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? 
            ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? 
            ?? 8D 85 ?? ?? ?? ?? 50 6A ?? FF B5 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 
            15 ?? ?? ?? ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? 6A ?? FF B5 ?? ?? ?? ?? 8B F0 FF 15 ?? 
            ?? ?? ?? 85 F6 0F 95 C3 E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 33 F6 89 B5 ?? ?? ?? ?? 56 53 FF
        }

        $encrypt_files_p2 = {
            15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 56 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 50 53 FF D7 85 C0 0F 84 ?? ?? ?? ?? 8D 56 ?? 8B 85 ?? ?? ?? 
            ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? 03 C8 8D 85 ?? ?? ?? ?? 
            3B 8D ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 50 6A ?? 0F 44 F2 56 6A ?? 
            FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            85 C0 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 
            ?? ?? ?? ?? 6A ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 53 FF D7 BA ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? 6A ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 
            15 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 53 FF D6 FF B5 
            ?? ?? ?? ?? FF D6 B3 ?? 8B 85 ?? ?? ?? ?? 83 F8 ?? 72 ?? 8B 8D ?? ?? ?? ?? 40 3D ?? 
            ?? ?? ?? 72 ?? F6 C1 ?? 75 ?? 8B 41 ?? 3B C1 73 ?? 2B C8 83 F9 ?? 72 ?? 83 F9 ?? 77 
            ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8A C3 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 
            8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C2
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_*)
        ) and
        (
            all of ($encrypt_files_p*)
        )
}
