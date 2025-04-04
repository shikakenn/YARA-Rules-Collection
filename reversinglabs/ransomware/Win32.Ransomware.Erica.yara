rule Win32_Ransomware_Erica : tc_detection malicious
{
    meta:
        id = "1ik5NYRmGftuJiGbOmmGX4"
        fingerprint = "v1_sha256_93512091943f3a3b395c38fa3b0f5ecdbbf1cdf967ccfea4d7145c940076e046"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Erica ransomware."
        category = "MALWARE"
        malware = "ERICA"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Erica"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            55 8B EC 83 C4 ?? 53 56 57 89 4D ?? 8B F2 8B D8 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 68 
            ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 89 45 ?? 8A 43 ?? 2C ?? 72 ?? 74 ?? EB ?? BF ?? 
            ?? ?? ?? EB ?? BF ?? ?? ?? ?? EB ?? BF ?? ?? ?? ?? 33 DB 68 ?? ?? ?? ?? 8B 45 ?? 50 
            8B 45 ?? 50 6A ?? 56 E8 ?? ?? ?? ?? 85 C0 74 ?? 8D 45 ?? 50 6A ?? 6A ?? 57 8B 06 50 
            E8 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 8D 45 ?? E8 ?? ?? ?? ?? 
            50 8B 45 ?? 50 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 45 ?? 50 6A ?? 8B 45 ?? 50 8B 45 ?? 50 
            8B 06 50 E8 ?? ?? ?? ?? 85 C0 75 ?? BB ?? ?? ?? ?? EB ?? BB ?? ?? ?? ?? EB ?? BB ?? 
            ?? ?? ?? EB ?? BB ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 33 C0 5A 
            59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? C3 
        }

        $encrypt_files_p2 = {
            8D 40 ?? 55 8B EC 83 C4 ?? 53 33 DB 89 5D ?? 89 5D ?? 8B D9 89 55 ?? 89 45 ?? 33 C0 
            55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 89 45 ?? 33 C0 89 45 ?? 33 C0 89 45 ?? 33 
            C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 ?? 50 8B 45 ?? 8D 50 ?? 8B 45 ?? 33 C9 
            E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 83 C0 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 
            40 ?? E8 ?? ?? ?? ?? 8B D0 4A 8B 45 ?? 83 C0 ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 40 ?? E8 
            ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 8B 45 ?? 8B 48 ?? 8B 45 ?? 8D 50 ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 85 C0 75 ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 
            ?? ?? ?? ?? 8B 45 ?? 50 53 8B 45 ?? 50 8B 45 ?? 50 8D 4D ?? 8D 55 ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 
            8B 45 ?? 50 8D 45 ?? 50 8B 45 ?? 83 C0 ?? E8 ?? ?? ?? ?? 50 6A ?? 6A ?? 6A ?? 8B 45 
            ?? 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 8B 45 ?? 83 C0 ?? 8B 55 ?? 
            E8 ?? ?? ?? ?? 8B 45 ?? 50 8D 45 ?? 50 8B 45 ?? 83 C0 ?? E8 ?? ?? ?? ?? 50 6A ?? 6A 
            ?? 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? EB ?? E8 ?? ?? ?? ?? 85 C0 74 ?? C7 45 ?? ?? ?? 
            ?? ?? 8B 45 ?? 83 C0 ?? 8B 55 ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? E8 ?? ?? ?? ?? EB 
            ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 83 C0 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? 
            ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 6A ?? 8B 45 
            ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 8D 50 ?? 8B 45 ?? 8B 4D ?? E8 ?? ?? 
            ?? ?? C3 
        }

        $find_files = {
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 33 DB 89 9D ?? ?? ?? ?? 89 5D ?? 8B D9 89 55 ?? 89 
            45 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 
            30 64 89 20 8B C3 E8 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 
            80 7C 02 ?? ?? 74 ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 45 
            ?? 80 38 ?? 75 ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? 
            ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 4D ?? 8B 55 ?? E8 ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? 50 8B 45 ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F0 85 F6 0F 95 C0 EB ?? F7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? 77 ?? 83 3B ?? 74 ?? 8B C3 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            FF 33 FF 75 ?? 8D 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? 8B C3 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 E8 ?? ?? 
            ?? ?? F7 D8 1B C0 F7 D8 84 C0 75 ?? 56 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        )
}
