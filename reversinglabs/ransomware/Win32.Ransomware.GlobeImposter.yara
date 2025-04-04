rule Win32_Ransomware_GlobeImposter : tc_detection malicious
{
    meta:
        id = "8VVROGUhiUpesU9bxpjSE"
        fingerprint = "v1_sha256_4345a767f270428f3b509fdad5a96bf9b494b190d3a836c4bf53dfd75da5bacb"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects GlobeImposter ransomware."
        category = "MALWARE"
        malware = "GLOBEIMPOSTER"
        tc_detection_type = "Ransomware"
        tc_detection_name = "GlobeImposter"
        tc_detection_factor = 5

    strings:

        $encrypt_files_1 = {
            81 EC ?? ?? ?? ?? 83 24 24 ?? 6A ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 44 24 
            ?? 50 E8 ?? ?? ?? ?? 8D 04 24 50 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 53 8B 1D ?? 
            ?? ?? ?? 55 56 57 8B 3D ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? 
            ?? ?? 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F0 8D 84 24 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 50 89 74 24 ?? FF D3 8D 44 24 ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 
            8B E8 83 FD ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D7 85 C0 0F 84 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 33 C0 66 89 84 
            74 ?? ?? ?? ?? 8D 44 24 ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF D3 6A ?? 8D 44 24 ?? 50 E8 
            ?? ?? ?? ?? F6 44 24 ?? ?? 8B F0 74 ?? 6A ?? 56 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 FF D3 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 
            50 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 56 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 8D 44 24 ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 
            50 FF D7 85 C0 0F 84 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 50 8D 44 24 ?? 
            50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 ?? A8 ?? 74 ?? 83 E0 ?? 50 8D 84 24 ?? ?? 
            ?? ?? 50 FF 15 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 6A ?? 56 E8 ?? ?? ?? ?? 50 FF B4 24 
            ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 85 C0 75 ?? 8D 84 24 ?? ?? ?? ?? 
            50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 
            50 FF D3 6A ?? 8D 84 24 ?? ?? ?? ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 
            84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B 74 24 ?? 59 8D 44 24 ?? 50 
            55 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 55 FF 15 ?? ?? ?? ?? 8D 44 24 ?? 50 E8 
            ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C2
        }

        $search_files_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 8B F8 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D8 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 33 F6 
            8D 85 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 DB 74 ?? F6 C3 ?? 74 ?? 8D 85 ?? 
            ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? 83 F8 ?? 74 ?? 83 F8 ?? 75 ?? 6A ?? 6A 
            ?? C6 85 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 89 
            04 B7 51 50 FF 15 ?? ?? ?? ?? 46 FE 85 ?? ?? ?? ?? D1 EB 75 ?? EB ?? 68 ?? ?? ?? ?? 
            FF 34 B7 FF 15 ?? ?? ?? ?? 85 C0 74 
        }

        $encrypt_files_2 = {
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 24 24 ?? 53 55 56 57 E8 ?? ?? ?? ?? 8B D0 8D 4C 24 
            ?? E8 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 1D ?? ?? ?? 
            ?? 8B 35 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 8D 84 24 ?? ?? 
            ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F8 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 89 7C 24 ?? 
            FF D3 8D 44 24 ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B E8 83 FD ?? 0F 84 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D6 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 8D 44 24 ?? 50 FF D6 85 C0 0F 84 ?? ?? ?? ?? 33 C0 66 89 84 7C ?? ?? ?? ?? 8D 44 
            24 ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF D3 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B F8 33 D2 F6 44 
            24 ?? ?? 8B CF 74 ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 
            ?? ?? ?? ?? 50 FF D3 8D 94 24 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 
            42 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D6 85 C0 
            0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D6 85 C0 0F 84 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? FF 15 ?? ?? ?? ?? 50 8D 44 24 ?? 50 FF D6 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 
            ?? A8 ?? 74 ?? 83 E0 ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 51 6A ?? 5A 8B 
            CF E8 ?? ?? ?? ?? 50 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8D 84 24 ?? ?? 
            ?? ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 84 24 ?? ?? 
            ?? ?? 50 FF D3 6A ?? 8D 84 24 ?? ?? ?? ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B 7C 24 ?? 59 8D 44 24 ?? 
            50 55 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 55 FF 15 ?? ?? ?? ?? 8D 4C 24 ?? E8 
            ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C2 
        }

        $kill_specific_processes_2 = {
            81 EC ?? ?? ?? ?? 56 57 6A ?? 5E 56 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 
            74 24 ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F8 83 FF ?? 0F 84 ?? ?? ?? ?? 8D 84 24 ?? 
            ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 53 55 BE ?? ?? ?? 
            ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 8B E8 33 D2 85 ED 7E ?? 0F BE 0C 1A E8 ?? ?? ?? ?? 88 04 1A 42 3B D5 7C ?? FF 36 
            53 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 83 C6 ?? 81 FE ?? ?? ?? ?? 7C ?? 85 C0 74 ?? 33 DB 
            53 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 FF 15 ?? ?? ?? ?? FF B4 
            24 ?? ?? ?? ?? 8B F0 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 68 ?? 
            ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 56 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8D 44 24 ?? 50 8D 
            44 24 ?? 50 53 53 68 ?? ?? ?? ?? 53 53 53 8D 84 24 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? 
            ?? 8D 84 24 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 57 FF 15 ?? 
            ?? ?? ?? 5D 5B 5F 5E 81 C4 ?? ?? ?? ?? C2
        }
        
        $kill_specific_processes_1 = {
            81 EC ?? ?? ?? ?? 55 56 57 6A ?? 5E 56 33 ED 8D 44 24 ?? 55 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 89 74 24 ?? 55 6A ?? E8 ?? ?? ?? ?? 8B F8 89 7C 24 ?? 83 FF ?? 0F 84 ?? ?? ?? ?? 
            53 8D 84 24 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 50 57 E8 ?? ?? ?? ?? 8B 5C 
            24 ?? 83 BC 24 ?? ?? ?? ?? ?? 8B F5 7E ?? 55 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 
            8B E8 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 33 DB 89 44 24 ?? 85 C0 7E ?? 8B F8 
            0F BE 0C 2B 51 E8 ?? ?? ?? ?? 88 04 2B 43 3B DF 7C ?? 8B 84 24 ?? ?? ?? ?? FF 34 B0 
            55 FF 15 ?? ?? ?? ?? 8B D8 85 DB 75 ?? 46 50 5D 3B B4 24 ?? ?? ?? ?? 7C ?? 8B 7C 24 
            ?? 33 ED 85 DB 74 ?? 55 68 ?? ?? ?? ?? 55 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 55 50 FF 
            15 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 8B F0 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 C4 
            ?? 8D 44 24 ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 56 8D 44 24 ?? 50 FF 15 ?? ?? ?? 
            ?? 8D 44 24 ?? 50 8D 44 24 ?? 50 55 55 68 ?? ?? ?? ?? 55 55 55 8D 84 24 ?? ?? ?? ?? 
            50 55 FF 15 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 57 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? 
            ?? ?? 57 FF 15 ?? ?? ?? ?? 5B 5F 5E 5D 81 C4 ?? ?? ?? ?? C2
        }

        $encrypt_files_3 = {
            68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 33 C0 66 89 84 74 ?? ?? 
            ?? ?? 8D 44 24 ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF D3 6A ?? 8D 44 24 ?? 50 E8 ?? ?? ?? 
            ?? F6 44 24 ?? ?? 8B F0 74 ?? 6A ?? 56 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 FF D3 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? 
            ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 56 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 8D 44 24 ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 
            D7 85 C0 0F 84 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 50 8D 44 24 ?? 50 FF 
            D7 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 ?? A8 ?? 74 ?? 83 E0 ?? 50 8D 84 24 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? FF 74 24 ?? 6A ?? 56 E8 ?? ?? ?? ?? 50 FF 74 24 ?? 8D 84 24 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 85 C0 75 ?? 8D 84 24 ?? ?? ?? ?? 50 8D 84 24 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 FF D3 6A ?? 8D 84 24 
            ?? ?? ?? ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 E8 
            ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B 74 24 ?? 59 8D 44 24 ?? 50 55 FF 15
        }
        
        $search_files_2 = {
            53 55 56 57 8B 3D ?? ?? ?? ?? 6A ?? 6A ?? FF D7 50 FF 15 ?? ?? ?? ?? 8B E8 FF 15 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 8B D8 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 33 F6 8D 84 24 ?? ?? 
            ?? ?? 56 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 DB 74 ?? F6 C3 ?? 74 ?? 8D 84 24 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? 83 F8 ?? 74 ?? 83 F8 ?? 75 ?? 6A ?? 6A ?? C6 84 
            24 ?? ?? ?? ?? ?? FF D7 50 FF 15 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 89 44 B5 ?? 51 50 
            FF 15 ?? ?? ?? ?? 46 FE 84 24 ?? ?? ?? ?? D1 EB 75 ?? 33 FF 85 F6 7E ?? 8B 9C 24 ?? 
            ?? ?? ?? 8D 44 24 ?? 2B E8 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 8C 
            24 ?? ?? ?? ?? 89 48 ?? 8D 0C BD ?? ?? ?? ?? 03 CD 89 58 ?? 8B 4C 0C ?? 89 08 33 C9 
            51 51 50 68 ?? ?? ?? ?? 51 51 FF 15 ?? ?? ?? ?? 89 44 BC ?? 47 3B FE 7C ?? 6A ?? 6A 
            ?? 8D 44 24 ?? 50 56 FF 15
        }

        $kill_specific_processes_3 = {
            E8 ?? ?? ?? ?? 83 C4 ?? 89 74 24 ?? 55 6A ?? E8 ?? ?? ?? ?? 8B F8 89 7C 24 ?? 83 FF 
            ?? 0F 84 ?? ?? ?? ?? 53 8D 84 24 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 50 57 
            E8 ?? ?? ?? ?? 8B 5C 24 ?? 83 BC 24 ?? ?? ?? ?? ?? 8B F5 7E ?? 55 8D 84 24 ?? ?? ?? 
            ?? 50 E8 ?? ?? ?? ?? 8B E8 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 33 DB 89 44 24 
            ?? 85 C0 7E ?? 8B F8 0F BE 0C 2B 51 E8 ?? ?? ?? ?? 88 04 2B 43 3B DF 7C ?? 8B 84 24 
            ?? ?? ?? ?? FF 34 B0 55 FF 15 ?? ?? ?? ?? 8B D8 85 DB 75 ?? 46 50 5D 3B B4 24 ?? ?? 
            ?? ?? 7C ?? 8B 7C 24 ?? 33 ED 85 DB 74 ?? 55 68 ?? ?? ?? ?? 55 FF 15 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 55 50 FF 15 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 8B F0 68 ?? ?? ?? ?? 56 FF 
            15 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 56 8D 44 24 
            ?? 50 FF 15 ?? ?? ?? ?? 8D 44 24 ?? 50 8D 44 24 ?? 50 55 55 68 ?? ?? ?? ?? 55 55 55 
            8D 84 24 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 57 E8 ?? ?? ?? 
            ?? 85 C0 0F 85 ?? ?? ?? ?? 57 FF 15
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (
                $search_files_1 and
                $encrypt_files_1 and
                $kill_specific_processes_1
            ) or
            (
                $search_files_1 and
                $encrypt_files_2 and
                $kill_specific_processes_2
            ) or
            (
                $search_files_2 and
                $encrypt_files_3 and
                $kill_specific_processes_3
            )
        )
}
