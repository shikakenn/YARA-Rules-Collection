rule Win32_Ransomware_PrincessLocker : tc_detection malicious
{
    meta:
        id = "FLJyF1ozcpn3VCLzfAtcs"
        fingerprint = "v1_sha256_5be4ca3bd0b0afed1d2f3a59e2951d74a8de94c5a4d5a2c6cc29add49eab9ec0"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects PrincessLocker ransomware."
        category = "MALWARE"
        malware = "PRINCESSLOCKER"
        tc_detection_type = "Ransomware"
        tc_detection_name = "PrincessLocker"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            6A ?? 6A ?? FF 15 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 
            6A ?? 6A ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? 
            ?? BA ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 45 ?? 83 7D ?? ?? 0F 43 45 
            ?? 50 53 FF D7 6A ?? FF B5 ?? ?? ?? ?? 8B F0 FF 15 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? 
            FF B5 ?? ?? ?? ?? FF D6 85 C0 75 ?? 83 7D ?? ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E9 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 6A ?? FF B5 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            85 C0 0F 84 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 
            8D 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 50 53 FF D7 68 ?? ?? ?? 
            ?? 8D 4D ?? 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8B D8 83 C4 ?? 89 9D ?? ?? ?? ?? 85 DB 75 ?? 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 
            4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? A1 ?? ?? 
            ?? ?? 8B 30 89 B5 ?? ?? ?? ?? 3B F0 0F 84 ?? ?? ?? ?? 33 C9 C6 45 ?? ?? 6A ?? 51 8D 
            46 ?? 66 89 8D ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8D 85 ?? ?? ?? ?? C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 50 6A ?? 8D 85 ?? ?? ?? 
            ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D0 C6 45 ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 83 BD ?? ?? ?? ?? ?? 72 ?? FF B5 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 7D ?? ?? 
            66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 50 FF 75 ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 83 EC ?? C6 45 ?? ?? 8B CC 
            33 C0 6A ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 50 66 89 01 8D 85 ?? ?? ?? ?? 
            50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? ?? ?? ?? EB ?? B8 ?? ?? ?? ?? 
            C3 C7 45 ?? ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 6A ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 8D 4D ?? 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 
            C4 ?? 68 ?? ?? ?? ?? 8B D0 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 
            45 ?? ?? 83 BD ?? ?? ?? ?? ?? 72 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 
            68 ?? ?? ?? ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D BD ?? ?? 
            ?? ?? 6A ?? 6A ?? 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 83 BD 
            ?? ?? ?? ?? ?? 6A ?? 0F 43 BD ?? ?? ?? ?? 6A ?? 50 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 
            85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 0F 84 ?? ?? ?? ?? 85 DB 0F 84 ?? ?? 
            ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 57 FF 15 ?? ?? ?? ?? 8B F8 83 FF 
            ?? 0F 84 ?? ?? ?? ?? 85 FF 0F 84 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? 
            ?? ?? 50 FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 85 
            ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 48 39 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? 
            0F B6 C9 0F 46 C8 8D 85 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? 0F B6 C1 6A ?? 50 6A ?? FF 
            B5 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? FF 95 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 FF B5 
            ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 57 FF 15
        }

        $remote_connection_1 = {
            6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 84 DB 0F 85 ?? ?? ?? 
            ?? 6A ?? 6A ?? 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? 88 5D ?? C7 45 ?? ?? 
            ?? ?? ?? 66 C7 45 ?? ?? ?? 88 5D ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 
            ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? 89 45 ?? E8 ?? ?? ?? ?? 8B F0 8D 55 ?? C6 45 ?? ?? 8D 8D ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B D0 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 56 8B D0 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8
        }

        $remote_connection_2 = {
            BA ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 66 C7 45 ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8D 55 ?? C6 45 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 BA ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B F0 8D 55 ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 
            8B D0 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 8B D0 C6 45 ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D0 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 53 8B D0 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? 
            ?? 51 8B D0 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D0 C6 45 ?? ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 50 E8
        }

    condition:
        uint16(0) == 0x5A4D and $encrypt_files and $remote_connection_1 and $remote_connection_2
}
