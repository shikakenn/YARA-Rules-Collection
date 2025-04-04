rule Win32_Ransomware_Crypren : tc_detection malicious
{
    meta:
        id = "6v3q0ulo0lnyEfJkGJDpbc"
        fingerprint = "v1_sha256_7047d48782762e42544063fde6f2be62eb19f22853ea84abb5bce67c962da172"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Crypren ransomware."
        category = "MALWARE"
        malware = "CRYPREN"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Crypren"
        tc_detection_factor = 5

    strings:

        $enum_directories_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 
            45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 
            45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7
        }

        $enum_directories_p2 = {
            85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 
            45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 85 ?? ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? C6
        }

        $enum_directories_p3 = { 
            45 ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 6A ?? 
            68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 
            ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? C7 45 ?? ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D BD ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? 90 83 7F ?? ?? 8B 5F ?? 72 ?? 8B 37 EB ?? 8B F7 83 7D ?? ?? 8D 
            45 ?? 8B D3 0F 43 45 ?? 3B CB 0F 42 D1 85 D2 74 ?? 83 EA ?? 72 ?? 8D 9B ?? ?? ?? ?? 
            8B 08 3B 0E 75 ?? 83 C0 ?? 83 C6 ?? 83 EA ?? 73 ?? 83 FA ?? 74 ?? 8A 08 3A 0E 75 ?? 
            83 FA ?? 74 ?? 8A 48 ?? 3A 4E ?? 75 ?? 83 FA ?? 74 ?? 8A 48 ?? 3A 4E ?? 75 ?? 83 FA 
            ?? 74 ?? 8A 40 ?? 3A 46 ?? 74 ?? 1B C0 83 C8 ?? EB ?? 33 C0 8B 4D ?? 85 C0 75 ?? 3B 
            CB 73 ?? 83 C8 ?? EB ?? 33 C0 3B CB 0F 95 C0 85 C0 0F 94 C0 84 C0 75 ?? 8B 85 ?? ?? 
            ?? ?? 83 C7 ?? 40 89 85 ?? ?? ?? ?? 83 F8 ?? 0F 82 ?? ?? ?? ?? B3 ?? EB ?? 32 DB 68 
            ?? ?? ?? ?? 6A ?? 6A ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 
            72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8A C3 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 
            5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $encrypt_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 6A ?? 8D 8D ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 33 FF C6 45 ?? ?? 83 7D ?? ?? 8D 45 ?? 6A 
            ?? 0F 43 45 ?? 8D 8D ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 6A ?? 
            0F 43 45 ?? 8D 8D ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8B 
            94 0D ?? ?? ?? ?? 85 D2 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? 39 BC 05 ?? ?? 
            ?? ?? 0F 85 ?? ?? ?? ?? F6 C2 ?? 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 03 C8 8D 45 ?? 
            50 E8 ?? ?? ?? ?? 50 C6 45 ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? C6 45 ?? ?? 8B F0 
            85 C9 74 ?? 8B 11 FF 52 ?? 85 C0 74 ?? 8B 10 8B C8 6A ?? FF 12 8B 06 8B CE 6A ?? 8B 
            40 ?? FF D0 88 45 ?? 8D 45 ?? FF 75 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 8D 4D ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 F6 39 75 ?? 76 ?? EB ?? 8D A4 24 
            ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 8D 4D ?? 0F 43 45 ?? 83 7D ?? ?? 0F 43 4D ?? 33 D2 
        }

        $encrypt_files_p2 = {
            0F BE 1C 30 8B C7 F7 75 ?? 8A 0C 0A 0F BE C1 03 C3 3D ?? ?? ?? ?? 7C ?? 25 ?? ?? ?? 
            ?? 79 ?? 48 0D ?? ?? ?? ?? 40 EB ?? 02 D9 0F B6 C3 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 46 83 C4 ?? 47 3B 75 ?? 72 ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? 8B 48 ?? F6 84 0D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 72 ?? FF 75 ?? E8 ?? ?? 
            ?? ?? 83 C4 ?? 83 7D ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 72 
            ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? C6 45 ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D 
            ?? ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? C6 45 ?? ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D 
            ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $enum_drives_p1 = {
            6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85  
        }

        $enum_drives_p2 = {
            E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6
            85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 
            4D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 
            ?? ?? ?? ?? 8D 4D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8  
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            (
                all of ($enum_directories_p*)
            ) and 
            (
                all of ($enum_drives_p*)
            ) and
            (
                all of ($encrypt_files_p*)
            )
        )
}
