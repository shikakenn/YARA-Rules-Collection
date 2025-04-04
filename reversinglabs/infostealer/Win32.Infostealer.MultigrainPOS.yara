rule Win32_Infostealer_MultigrainPOS : tc_detection malicious
{
    meta:
        id = "5gY8qP4laJxn0rany1x7Xk"
        fingerprint = "v1_sha256_9808c95b850a54677c4132057b8372cabf0159920b7e0e6834a83f0d39c088fa"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects MultigrainPOS infostealer."
        category = "MALWARE"
        malware = "MULTIGRAINPOS"
        tc_detection_type = "Infostealer"
        tc_detection_name = "MultigrainPOS"
        tc_detection_factor = 5

    strings:
        $data_exfiltration_v10_1 = {
            55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 8B 1D ?? ?? ?? ?? 56 57 8B 3D ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 6A ?? 8D 4D ?? 51 6A ?? 6A ?? 8D 45 ?? 0F 
            43 45 ?? 6A ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 85 C0 75 ?? 8B 45 ?? 50 8B 70 ?? FF D7 81 
            FE ?? ?? ?? ?? 74 ?? 81 FE ?? ?? ?? ?? 75 ?? 83 7D ?? ?? 5F 5E 5B 72 ?? FF 75 ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 33 CD B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B E5 5D C2 ?? ?? 
            FF 75 ?? FF D7 68 ?? ?? ?? ?? FF D3 EB
        }

        $memory_scraping_v10_1 = {
            6A ?? 56 8B CF E8 ?? ?? ?? ?? 85 C0 75 ?? 6A ?? 56 8B CF E8 ?? ?? ?? ?? 8B 8D ?? ?? 
            ?? ?? EB ?? 3C ?? 7C ?? 3C ?? 7E ?? 8A 46 ?? 3C ?? 7C ?? 3C ?? 7E ?? 3C ?? 74
        }

        $process_search_v10_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 56 57 68 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F0 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 
            85 C0 74 ?? 8B 3D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF D7 85 C0 74 ?? 8B 1D ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 50 FF D3 85 C0 74 ?? 8D 
            85 ?? ?? ?? ?? 50 56 FF D7 85 C0 75
        }

        $service_creation_v10_1 = {
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 50 8D 4C 24 ?? C7 44 24 ?? ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 33 C0 5E 8B 4C 24 ?? 33 CC E8 ?? ?? 
            ?? ?? 8B E5 5D C3 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 8D 44 24 ?? 50 C7 44 24 ?? 
            ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 
            FF 15
        }


        $process_search_v11_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 56 57 8B 7D ?? FF 15 ?? 
            ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? EB ?? 8D 49 ?? 68 ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 6A ?? 
            FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 F8 ?? 75 ?? 68 ?? ?? ?? ?? FF D3 EB ?? 8D 8D 
            ?? ?? ?? ?? 51 50 FF 15 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 33 C0 68 ?? ?? ?? ?? 50 66 89 
            85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 33 C9 EB ?? 8D A4 24 ?? 
            ?? ?? ?? EB ?? 8D 49 ?? 0F B7 84 0D ?? ?? ?? ?? 66 89 84 0D ?? ?? ?? ?? 8D 49 ?? 66 
            85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15
        }

        $memory_scraping_v11_1 = {
            6A ?? 56 8B CF E8 ?? ?? ?? ?? 6A ?? 56 8B CF E8 ?? ?? ?? ?? EB ?? 3C ?? 75 ?? 6A ?? 
            56 8B CF E8 ?? ?? ?? ?? 6A ?? 56 8B CF E8
        }

        $data_exfiltration_v11_1 = {
            55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 8A 5D ?? 56 57 8B 3D ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 6A ?? 8D 4D ?? 51 6A ?? 6A ?? 8D 45 ?? 0F 43 45 ?? 
            6A ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 85 C0 75 ?? 8B 45 ?? 50 8B 70 ?? FF D7 81 FE ?? ?? 
            ?? ?? 74 ?? 81 FE ?? ?? ?? ?? 74 ?? 84 DB 74 ?? 33 F6 83 7D ?? ?? 72 ?? FF 75 ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 5F 8B C6 5E 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C2 ?? ?? 
            FF 75 ?? FF D7 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 84 DB 74 ?? EB ?? BE ?? ?? ?? ?? EB
        }

        $service_creation_v11_1 = {
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 50 8D 4C 24 ?? C7 44 24 ?? ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 33 C0 8B 4C 24 ?? 33 CC E8 ?? ?? ?? 
            ?? 8B E5 5D C3 8D 44 24 ?? 50 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 
            24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF 15 
        }

    condition:
            uint16(0) == 0x5A4D and
            (($data_exfiltration_v10_1 and $memory_scraping_v10_1 and $process_search_v10_1 and $service_creation_v10_1) or
            ($process_search_v11_1 and $memory_scraping_v11_1 and $data_exfiltration_v11_1 and $service_creation_v11_1))
}
