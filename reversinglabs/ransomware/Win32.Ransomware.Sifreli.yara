rule Win32_Ransomware_Sifreli : tc_detection malicious
{
    meta:
        id = "4Mp3YF0572BYM4VaySLx1L"
        fingerprint = "v1_sha256_48f6cc678bea81afece0ae203fb27b61e2c6e4f7188a3bd260190f568c9a8a06"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Sifreli ransomware."
        category = "MALWARE"
        malware = "SIFRELI"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Sifreli"
        tc_detection_factor = 5

    strings:

        $find_files = {                        
            55 8B EC 83 EC ?? 53 56 57 8B 7D ?? 8B C7 8D 50 ?? 66 8B 08 83 C0 ?? 66 85 C9 75 ?? 
            2B C2 D1 F8 8D 44 00 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 
            6A ?? 50 FF D6 8B D8 89 5D ?? 85 DB 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 53 FF 15 ?? 
            ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 51 FF D6 8B F8 85 FF 0F 84 ?? ?? ?? 
            ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? E8 ?? ?? ?? ?? 3D ?? ?? 
            ?? ?? 1B C0 40 A3 ?? ?? ?? ?? EB ?? A1 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 57 50 53 FF 15 
            ?? ?? ?? ?? 89 45 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 90 F6 07 ?? 74 
            ?? BB ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 47 ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 
            8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 33 DB EB ?? 
            1B C0 83 D8 ?? 85 C0 74 ?? B9 ?? ?? ?? ?? 8D 47 ?? 8D 49 ?? 66 8B 10 66 3B 11 75 ?? 
            66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 
            EB ?? 1B C0 83 D8 ?? 85 C0 74 ?? 8B 55 ?? 8B 4D ?? 52 8D 47 ?? 50 8B 07 50 53 68 ?? 
            ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8B 55 ?? 57 52 FF 15 ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 5D ?? EB ?? C7 45 ?? ?? ?? ?? 
            ?? 8B 0D ?? ?? ?? ?? 57 6A ?? 51 FF 15 ?? ?? ?? ?? EB ?? C7 45 ?? ?? ?? ?? ?? 8B 15 
            ?? ?? ?? ?? 53 6A ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 5F 5E 5B 8B E5 5D C3 5F 5E B8 ?? 
            ?? ?? ?? 5B 8B E5 5D C3 
        }

        $remote_connection_p1 = {                        
            55 8B EC 83 EC ?? 53 33 DB 8D 45 ?? 89 5D ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 
            8B 45 ?? 8B 4D ?? 56 57 50 51 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 8B 55 ?? 8B 
            4D ?? 52 57 E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 74 ?? 8B 45 ?? 6A 
            ?? 50 6A ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B D6 E8 ?? ?? ?? ?? 85 C0 74 ?? 
            C7 45 ?? ?? ?? ?? ?? 56 FF D3 8D 4D ?? 51 8D 55 ?? 52 6A ?? 57 C7 45 ?? ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 57 8B F0 FF D3 85 F6 74 ?? 8B 45 ?? 50 FF D3 
            8B 5D ?? 83 7D ?? ?? 8B 35 ?? ?? ?? ?? 74 ?? 8B 4D ?? 8B 15 ?? ?? ?? ?? 51 6A ?? 52 
            FF D6 8B 45 ?? 85 C0 74 ?? 50 A1 ?? ?? ?? ?? 6A ?? 50 FF D6 5F 5E 8B C3 5B 8B E5 5D 
            C3 8B C3 5B 8B E5 5D C3 
        }

        $remote_connection_p2 = {                        
            55 8B EC 83 EC ?? 56 57 68 ?? ?? ?? ?? 33 FF 57 57 57 57 FF 15 ?? ?? ?? ?? 8B F0 85 
            F6 74 ?? 8B 3D ?? ?? ?? ?? B8 ?? ?? ?? ?? 6A ?? 89 45 ?? 89 45 ?? 8D 45 ?? 50 6A ?? 
            56 C7 45 ?? ?? ?? ?? ?? FF D7 6A ?? 8D 4D ?? 51 6A ?? 56 FF D7 6A ?? 8D 55 ?? 52 6A 
            ?? 56 FF D7 8B 45 ?? 8B 4D ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 50 51 56 FF 15 ?? ?? ?? 
            ?? 8B F8 85 FF 75 ?? 56 FF 15 ?? ?? ?? ?? 8B C7 5F 5E 8B E5 5D C3 
        }

        $remote_connection_p3 = {                        
            55 8B EC 83 EC ?? 53 56 8B F0 33 C0 89 06 57 89 46 ?? 89 46 ?? 6A ?? 50 89 46 ?? 8D 
            45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 51 6A ?? BF ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 89 7D ?? 89 7D ?? 89 7D ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? 
            ?? ?? ?? 8B 4D ?? 8B 1D ?? ?? ?? ?? 8D 4C 09 ?? 33 C0 85 C9 74 ?? 8B 15 ?? ?? ?? ?? 
            51 50 52 FF D3 89 06 85 C0 0F 84 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 51 52 50 E8 ?? ?? ?? 
            ?? 8B 06 8B 55 ?? 33 C9 66 89 0C 50 8B 4D ?? 83 C4 ?? 85 C9 74 ?? 8B 45 ?? 66 83 38 
            ?? 75 ?? 83 45 ?? ?? 2B CF 89 4D ?? 85 C9 75 ?? 8B 55 ?? 8D 7C 0A ?? 8D 54 3F ?? 33 
            C0 85 D2 74 ?? 52 50 A1 ?? ?? ?? ?? 50 FF D3 8B 4D ?? 89 46 ?? 85 C0 74 ?? 51 8B 4D 
            ?? 51 83 C0 ?? 50 E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 8B 4E ?? 52 8B 55 ?? 50 8D 44 51 
            ?? 50 E8 ?? ?? ?? ?? 8B 46 ?? B9 ?? ?? ?? ?? 66 89 08 33 D2 66 89 14 78 66 8B 45 ?? 
            83 C4 ?? 83 7D ?? ?? 66 89 46 ?? 75 ?? 83 4E ?? ?? 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D 
            C3 8B 36 85 F6 74 ?? 8B 0D ?? ?? ?? ?? 56 6A ?? 51 FF 15 ?? ?? ?? ?? 5F 5E 33 C0 5B 
            8B E5 5D C3 
        }

        $encrypt_files_1 = {                        
            8B C3 8D 50 ?? 66 8B 08 83 C0 ?? 66 85 C9 75 ?? 2B C2 D1 F8 57 8B F8 8D 4C 3F ?? 33 
            C0 85 C9 74 ?? 51 50 A1 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 56 8B F0 8B CB 
            2B F3 8D 9B ?? ?? ?? ?? 0F B7 11 66 89 14 0E 83 C1 ?? 66 85 D2 75 ?? B9 ?? ?? ?? ?? 
            8D 34 3F 2B F1 03 F0 EB ?? 8D 49 ?? 0F B7 11 66 89 14 0E 83 C1 ?? 66 85 D2 75 ?? 5E 
            5F C3 
        }

        $encrypt_files_2 = {                        
            83 E8 ?? 53 56 57 8B DA 74 ?? 48 74 ?? 5F 5E 33 C0 5B C3 53 51 33 F6 E8 ?? ?? ?? ?? 
            83 C4 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 8B F0 33 FF 85 F6 74 ?? 56 53 FF 15 ?? ?? ?? ?? 
            85 C0 74 ?? BF ?? ?? ?? ?? A1 ?? ?? ?? ?? 56 6A ?? 50 FF 15 ?? ?? ?? ?? 8B F7 5F 8B 
            C6 5E 5B C3 53 51 33 F6 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 8B F0 33 
            FF 85 F6 74 ?? 56 53 FF 15 ?? ?? ?? ?? 85 C0 74 ?? BF ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 
            56 6A ?? 51 FF 15 ?? ?? ?? ?? 8B F7 5F 8B C6 5E 5B C3 ?? ?? 55 8B EC 8B 4D ?? 8B 41 
            ?? 83 F8 ?? 0F 8F ?? ?? ?? ?? F7 45 ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 40 53 89 41 ?? 
            8B 45 ?? 83 E8 ?? 56 57 74 ?? 48 0F 85 ?? ?? ?? ?? 8B 7D ?? 33 F6 8D 9B ?? ?? ?? ?? 
            8B 86 ?? ?? ?? ?? 50 57 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 C6 ?? 83 
            FE ?? 72 ?? 8B 5D ?? E8 ?? ?? ?? ?? 8B F0 85 F6 74 ?? 8B 4D ?? 51 56 E8 ?? ?? ?? ?? 
            83 C4 ?? EB ?? 8B 41 ?? 83 E8 ?? 74 ?? 48 75 ?? 8B 75 ?? E8 ?? ?? ?? ?? EB ?? 8B 75 
            ?? 8B C6 E8 ?? ?? ?? ?? F7 D8 1B C0 F7 D8 85 C0 74 ?? 8B 5D ?? 8B FE E8 ?? ?? ?? ?? 
            8B F0 85 F6 74 ?? 8B 7D ?? 8B 47 ?? 8B 0F 8B D6 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 47 ?? 
            85 C0 74 ?? 50 FF 15 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? 8B 45 ?? FF 48 ?? 5F 5E 5B B8 
            ?? ?? ?? ?? 5D C3 
        }

        $encrypt_files_3 = {                        
            8B C6 8D 50 ?? 66 8B 08 83 C0 ?? 66 85 C9 75 ?? 2B C2 D1 F8 83 C0 ?? 85 C0 7E ?? EB 
            ?? 8D 49 ?? 66 83 3C 46 ?? 74 ?? 48 85 C0 7F ?? 33 C0 C3 8D 44 46 ?? 85 C0 74 ?? 83 
            C0 ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? B8 ?? ?? ?? ?? C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $find_files
        ) and 
        (
            all of ($encrypt_files_*)
        ) and 
        (
            all of ($remote_connection_p*)
        )
}
