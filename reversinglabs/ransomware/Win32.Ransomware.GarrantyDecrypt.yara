rule Win32_Ransomware_GarrantyDecrypt : tc_detection malicious
{
    meta:
        id = "3XnPdKHRID1krrg9bT8qHc"
        fingerprint = "v1_sha256_7194c1e0e15a89f2c691a7d586b9db68295cc52a5f042d0f7eb558c326430444"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects GarrantyDecrypt ransomware."
        category = "MALWARE"
        malware = "GARRANTYDECRYPT"
        tc_detection_type = "Ransomware"
        tc_detection_name = "GarrantyDecrypt"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 
            35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 33 DB 53 53 8D 45 ?? 50 89 5D ?? FF D6 85 C0 75 
            ?? 68 ?? ?? ?? ?? 6A ?? 53 53 8D 45 ?? 50 FF D6 85 C0 74 ?? 8B 45 ?? A3 ?? ?? ?? ?? 
            3B C3 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 3B F3 0F 84 ?? ?? ?? ?? 8B 7E ?? 8B 46 
            ?? 33 C9 3B FB 76 ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 29 45 ?? 8B 55 ?? 8D 84 0D ?? ?? ?? 
            ?? 8A 14 02 41 88 10 3B CF 72 ?? 68 ?? ?? ?? ?? 53 53 FF 76 ?? FF 36 FF 35 ?? ?? ?? 
            ?? FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 3B FB 74 ?? 8B 46 ?? 68 ?? ?? ?? ?? 89 45 
            ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 53 6A ?? 53 57 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 
            45 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? FF 36 E8 
            ?? ?? ?? ?? FF 76 ?? E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? ?? 53 FF 
            35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 53 FF 15 
        }

        $encrypt_files_p2 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8D 45 ?? 50 6A ?? 5F 57 FF 35 ?? ?? ?? ?? FF 15 
            ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 58 E8 ?? ?? ?? ?? 8B C8 33 DB 89 4D ?? 3B 
            CB 0F 84 ?? ?? ?? ?? 8D 45 ?? 89 7D ?? 8B F1 2B C1 8A 14 30 88 16 46 4F 75 ?? 6A ?? 
            8D 45 ?? 50 51 53 6A ?? 53 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 75 ?? 53 68 ?? ?? 
            ?? ?? 6A ?? 53 6A ?? 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 89 45 ?? 83 F8 ?? 0F 84 ?? 
            ?? ?? ?? 89 5D ?? 89 5D ?? 8B 3D ?? ?? ?? ?? 56 FF D7 8D 04 46 83 E8 ?? 66 83 38 ?? 
            75 ?? 8B 4D ?? FF B1 ?? ?? ?? ?? 2B C6 83 C0 ?? D1 F8 8D 04 46 50 FF 15 ?? ?? ?? ?? 
            3B C3 74 ?? 50 FF D7 8B 4D ?? FF B1 ?? ?? ?? ?? 89 45 ?? FF D7 39 45 ?? 74 ?? 83 45 
            ?? ?? 83 7D ?? ?? 72 ?? EB ?? C7 45 ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 
            3D ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 89 45 ?? 3B C3 0F 84 ?? ?? ?? ?? 53 8D 45 ?? 50 68 
            ?? ?? ?? ?? FF 75 ?? FF 75 ?? FF 15 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 33 C0 89 5D ?? 3B 
            C3 72 ?? 77 ?? 39 5D ?? 76 ?? 8B 45 ?? 8B C8 81 E1 ?? ?? ?? ?? 79 ?? 49 83 C9 ?? 41 
            89 4D ?? 75 ?? 99 83 E2 ?? 03 C2 C1 F8 ?? 99 52 50 8D 85 ?? ?? ?? ?? 50 8D 45 ?? E8 
            ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? 8B 55 ?? 8B 45 ?? 8A 8C 0D ?? ?? ?? ?? 30 0C 10 FF 45 
            ?? 8B 45 ?? 99 33 C9 3B D1 72 ?? 77 ?? 3B 45 ?? 72 ?? 8B 45 ?? 6A ?? F7 D8 99 53 52 
            50 FF 75 ?? FF D7 53 8D 45 ?? 50 FF 75 ?? FF 75 ?? FF 75 ?? FF D6 39 5D ?? 74 ?? 81 
            7D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 59 6A ?? 53 53 33 C0 50 
            FF 75 ?? C7 45 ?? ?? ?? ?? ?? FF D7 53 8D 45 ?? 50 6A ?? 8D 45 ?? 50 FF 75 ?? FF D6 
            53 8D 45 ?? 50 6A ?? FF 75 ?? FF 75 ?? FF D6 FF 75 ?? FF 15 ?? ?? ?? ?? B8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B F0 3B F3 74 ?? 68 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 56 FF 15 ?? ?? ?? ?? 83 C4 ?? 56 FF 75 ?? FF 15 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 
            59 FF 75 ?? E8 ?? ?? ?? ?? 59 5F 5E 5B C9 C3 
        }

        $find_files = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 89 5D ?? 85 
            DB 0F 84 ?? ?? ?? ?? FF 75 ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? BF ?? ?? ?? ?? 57 53 
            FF D6 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 89 45 ?? 83 F8 ?? 0F 84 ?? 
            ?? ?? ?? BB ?? ?? ?? ?? 83 65 ?? ?? 8B 45 ?? FF B0 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 
            FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 83 45 ?? ?? 83 7D ?? ?? 72 ?? 8D 85 ?? ?? 
            ?? ?? 50 FF 75 ?? 53 57 FF 75 ?? FF D6 83 C4 ?? F6 85 ?? ?? ?? ?? ?? 74 ?? 68 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF 75 ?? E8 ?? ?? ?? ?? EB ?? 68 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? F6 85 ?? ?? ?? ?? ?? 74 ?? FF 75 
            ?? E8 ?? ?? ?? ?? 59 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? 
            ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 75 ?? 53 57 FF 75 ?? FF D6 83 
            C4 ?? 33 F6 56 68 ?? ?? ?? ?? 6A ?? 56 6A ?? 68 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? 
            ?? 8B D8 83 FB ?? 74 ?? 56 8B 35 ?? ?? ?? ?? 8D 45 ?? 50 BF ?? ?? ?? ?? 57 FF D6 50 
            57 8B 3D ?? ?? ?? ?? 53 FF D7 6A ?? 8D 45 ?? 50 FF 35 ?? ?? ?? ?? FF D6 50 FF 35 ?? 
            ?? ?? ?? 53 FF D7 53 FF 15 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 59 5F 5E 5B C9 C3 
        }

    condition:
        uint16(0) == 0x5A4D and $find_files and (all of ($encrypt_files_p*))
}
