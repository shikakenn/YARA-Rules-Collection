rule Win32_Ransomware_KillDisk : tc_detection malicious
{
    meta:
        id = "5dlZbFLDqXD5WqOysvggp7"
        fingerprint = "v1_sha256_6148e6fc1363ff8995a9100e07139bfa658c72892db4d30a973bad0f2b3e6c3f"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects KillDisk ransomware."
        category = "MALWARE"
        malware = "KILLDISK"
        mitre_att = "S0607"
        tc_detection_type = "Ransomware"
        tc_detection_name = "KillDisk"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 8B AC 24 ?? ?? ?? 
            ?? 56 57 33 FF 8B F1 3B F7 89 7D ?? 89 7D ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 56 
            FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 95 C0 84 C0 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 56 8D 
            4C 24 ?? 89 7C 24 ?? 89 7C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 84 C0 74 ?? B8 ?? ?? ?? ?? 
            E9 ?? ?? ?? ?? 8B 5C 24 ?? 3B DF 8B 44 24 ?? 89 45 ?? 89 5D ?? 77 ?? 83 F8 ?? 0F 82 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 6A ?? 57 6A ?? 68 ?? ?? ?? ?? 56 FF 15 
            ?? ?? ?? ?? 8B E8 3B EF 0F 84 ?? ?? ?? ?? 83 FD ?? 0F 84 ?? ?? ?? ?? 8B 0D ?? ?? ?? 
            ?? 33 C0 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 
            44 24 ?? 89 44 24 ?? 8D 44 24 ?? 50 6A ?? 51 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 54 
            24 ?? 57 52 E8 ?? ?? ?? ?? 83 C4 ?? 8D 54 24 ?? 8D 44 24 ?? E8 ?? ?? ?? ?? 85 C0 0F 
            85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 
            4C 24 ?? 51 8D 54 24 ?? 89 7C 24 ?? 52 8D BC 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            85 C0 0F 84 ?? ?? ?? ?? 8B 74 24 ?? 6A ?? 8B C6 05 ?? ?? ?? ?? 50 8B CB 83 D1 ?? 51 
            6A ?? 6A ?? 55 FF 15 ?? ?? ?? ?? 85 C0 89 44 24 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 
            ?? ?? ?? ?? 8D 4C 24 ?? 51 53 56 8B F8 E8 ?? ?? ?? ?? 83 C4 ?? 84 C0 0F 84 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 8D 54 24 ?? 6A ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? B9 ?? ?? ?? ?? 8D B4 
            24 ?? ?? ?? ?? 8D 7C 24 ?? 8D 44 24 ?? F3 A5 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 08 89 8C 24 ?? ?? ?? ?? 8B 50 ?? 89 94 24 ?? ?? ?? ?? 8B 48 ?? 89 8C 24 
            ?? ?? ?? ?? 8B 50 ?? 89 94 24 ?? ?? ?? ?? 8B 48 ?? 89 8C 24 ?? ?? ?? ?? 8B 50 ?? 8D 
            74 24 ?? 89 94 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 6A ?? 6A ?? 53 50 55 FF 15 
            ?? ?? ?? ?? 6A ?? 8D 4C 24 ?? 51 68 ?? ?? ?? ?? 8D 54 24 ?? 52 55 C7 44 24 ?? ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 8B F0 8B 44 24 ?? F7 DE 1B F6 83 E6 ?? 50 83 C6 ?? FF 15 ?? 
            ?? ?? ?? 55 FF 15 ?? ?? ?? ?? 8B C6 EB ?? 8B 44 24 ?? 50 BE ?? ?? ?? ?? FF 15 ?? ?? 
            ?? ?? 55 FF 15 ?? ?? ?? ?? 8B C6 EB ?? 55 BE ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B C6 EB 
            ?? 55 BE ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B C6 EB ?? 55 BE ?? ?? ?? ?? FF 15 ?? ?? ?? 
            ?? 8B C6 EB ?? BE ?? ?? ?? ?? 8B C6 EB ?? B8 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 5F 5E 
            5D 5B 33 CC E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? C3 
        }

        $app_whitelisting_1 = {
            81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 32 DB FF 15 
            ?? ?? ?? ?? 6A ?? 6A ?? 89 44 24 ?? FF 15 ?? ?? ?? ?? 8B E8 85 ED 89 6C 24 ?? 0F 84 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4C 24 ?? 
            51 55 C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 64 24 ?? 
            8B 54 24 ?? 3B 54 24 ?? 0F 84 ?? ?? ?? ?? B8 ?? ?? ?? ?? 33 FF E8 ?? ?? ?? ?? 85 C0 
            0F 86 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 85 DB 0F 84 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B C1 
            2B C3 C1 F8 ?? 3B C7 0F 86 ?? ?? ?? ?? 3B D9 8B F3 76 ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? 
            ?? ?? 8B 0D ?? ?? ?? ?? 89 74 24 ?? 8D 34 BE 3B F1 B8 ?? ?? ?? ?? 8B E8 77 ?? 3B F3 
            73 ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 3B 75 ?? 72 ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? 
            ?? 8B 44 24 ?? 39 06 74 ?? B8 ?? ?? ?? ?? 83 C7 ?? E8 ?? ?? ?? ?? 3B F8 72 ?? 8B 6C 
            24 ?? 8B 74 24 ?? FF 15 ?? ?? ?? ?? 3B F0 74 ?? 85 F6 74 ?? 56 6A ?? 6A ?? FF 15 ?? 
            ?? ?? ?? 8B F0 85 F6 74 ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? EB ?? 8B 
            6C 24 ?? 8D 4C 24 ?? 51 55 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? B3 ?? 55 FF 15 
            ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 5F 5E 5D 8A C3 5B 33 CC E8 ?? ?? ?? ?? 81 C4 ?? ?? 
            ?? ?? C3 
        }

        $app_whitelisting_2 = {
            6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? 56 A1 ?? ?? ?? ?? 33 C4 50 8D 44 
            24 ?? 64 A3 ?? ?? ?? ?? 8D 44 24 ?? 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 70 ?? C7 44 
            24 ?? ?? ?? ?? ?? 56 C7 06 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 84 C0 74 ?? 8B 36 EB 
            ?? 33 F6 6A ?? 56 FF 15 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 8B 44 24 ?? 85 C0 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 7C 24 ?? ?? 72 ?? 8B 4C 24 
            ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 4C 24 ?? 64 89 0D 
            ?? ?? ?? ?? 59 5E 83 C4 ?? C3 
        }

    condition:
        uint16(0) == 0x5A4D and $encrypt_files and $app_whitelisting_1 and $app_whitelisting_2
}
