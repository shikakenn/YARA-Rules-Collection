rule Win32_Ransomware_Marlboro : tc_detection malicious
{
    meta:
        id = "7LDHlnD7Q8YB9gjuEDzvv5"
        fingerprint = "v1_sha256_d36c3cf52af47e9f638f58aabc19298e8c58831c3083f82e4c194319503eeaaa"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Marlboro ransomware."
        category = "MALWARE"
        malware = "MARLBORO"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Marlboro"
        tc_detection_factor = 5

    strings:

        $ping_apnic = {
            55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 6A ?? 8D 85 ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 0F 57 
            C0 F3 0F 7F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 6A ?? FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 
            85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 
            8D 85 ?? ?? ?? ?? 50 6A ?? FF 15 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $remote_server_connection_1 = {
            BA ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D7 8B C8 E8 ?? ?? ?? ?? BA ?? ?? 
            ?? ?? 8B C8 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D6 8B 
            C8 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 8D 55 ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? C6 45 ?? ?? 8D 55 ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 8B 40 ?? F6 84 05 ?? ?? ?? ?? ?? 74 ?? 83 EC ?? 8D 45 ?? 8D 4D ?? 
            50 E8 ?? ?? ?? ?? C6 45 ?? ?? BA ?? ?? ?? ?? 8B C8 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 
        }

        $remote_server_connection_2 = {
            84 C0 74 ?? B3 ?? EB ?? 32 DB C7 45 ?? ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? 74 ?? 83 7D 
            ?? ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 84 DB 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3D ?? ?? ?? 
            ?? 74 ?? 8D 80 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? [0-3] 8B 85 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 40 ?? 03 C8 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 50 C6 
            45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 83 C4 ?? 8B 8D ?? ?? ?? ?? 8B F0 85 C9 74 ?? 8B 
            01 FF 50 ?? 85 C0 74 ?? 8B 10 8B C8 6A ?? FF 12 8B 06 8B CE 6A ?? 8B 40 ?? FF D0 
        }

        $remote_server_connection_3 = {
            50 8D 55 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5D ?? 83 C4 ?? 8B 7D ?? 8B 08 8B 49 
            ?? F6 44 01 ?? ?? 75 ?? 8B 75 ?? 8D 4D ?? 83 FB ?? B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 0F 
            43 CF 3B F0 0F 42 C6 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 83 FE ?? 73 ?? 83 C8 ?? 
            EB ?? 33 C0 83 FE ?? 0F 95 C0 85 C0 0F 94 C0 84 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 
            B5 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 83 FB ?? 72 
        }

        $remote_server_connection_4 = {
            57 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 7D 
            ?? ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 
            C6 EB ?? 8B 8D ?? ?? ?? ?? 8B 01 FF 50 ?? 8B 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? 
            ?? ?? ?? C3 8B 85 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 
            CD E8 ?? ?? ?? ?? 8B E5 5D 
        }
        
        $encrypt_file = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 51 C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 
            8B 35 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            C6 45 ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 45 ?? 83 7D ?? ?? 51 0F 43 45 ?? 8D 8D ?? ?? ?? 
            ?? 6A ?? 50 E8 ?? ?? ?? ?? 85 C0 8D 8D ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BF ?? ?? ?? ?? 
            8B 40 ?? 75 ?? 03 C8 8B 41 ?? 83 C8 ?? 83 79 ?? ?? 75 ?? 0B C7 EB ?? 03 C8 33 C0 39 
            41 ?? 0F 44 C7 6A ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 51 0F 43 45 ?? 8D 8D ?? 
            ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 85 C0 8D 8D ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? 
            75 ?? 03 C8 8B 41 ?? 83 C8 ?? 83 79 ?? ?? 75 ?? 83 C8 ?? EB ?? 03 C8 33 C0 39 41 ?? 
            0F 44 C7 6A ?? 50 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 6A ?? 83 EC 
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 6A ?? 83 EC ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 8D 8D ?? ?? 
            ?? ?? 50 E8 ?? ?? ?? ?? 8B 08 8B 49 ?? F6 44 01 ?? ?? 75 ?? 8D 64 24 ?? 51 8D 55 ?? 
            8B CE E8 ?? ?? ?? ?? 51 8D 45 ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 
            ?? 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 08 8B 49 ?? F6 44 01 ?? ?? 74 ?? 8D 8D ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 40 ?? 03 
            C8 8B 41 ?? 83 C8 ?? 83 79 ?? ?? 75 ?? 83 C8 ?? 6A ?? 50 E8 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 40 ?? 03 C8 
            8B 41 ?? 83 C8 ?? 83 79 ?? ?? 75 ?? 83 C8 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 
            45 ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? C6 45 ?? ?? 83 C4 ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? 
            C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? ?? 
            ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 83 C4 ?? 8B 85 ?? 
            ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 
            ?? 89 84 0D ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? 
            C7 84 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? 
            ?? ?? 8D 45 ?? 50 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 72 ?? FF 
            75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? C7 45 ?? ?? ?? 
            ?? ?? 66 89 45 ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D ?? ?? ?? 
            ?? 59 5F 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and $ping_apnic and 
        $remote_server_connection_1 and 
        $remote_server_connection_2 and 
        $remote_server_connection_3 and 
        $remote_server_connection_4 and
        $encrypt_file
}
