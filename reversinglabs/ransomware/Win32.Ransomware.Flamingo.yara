rule Win32_Ransomware_Flamingo : tc_detection malicious
{
    meta:
        id = "6X5PWpIFNXNL3w4ERCmbGm"
        fingerprint = "v1_sha256_446c0d332af01c0fceb0356d5ab273eb55764869cc8343468b75625e5d4d1036"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Flamingo ransomware."
        category = "MALWARE"
        malware = "FLAMINGO"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Flamingo"
        tc_detection_factor = 5

    strings:

        $find_files = {
            68 ?? ?? ?? ?? 1B C0 23 C1 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 8D 85 ?? ?? ?? ?? 57 57 57 50 57 53 FF 15 ?? ?? ?? ?? 8B F0 8B 85 ?? ?? ?? 
            ?? 83 FE ?? 75 ?? 50 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 83 FE ?? 74 ?? 56 FF 15 
            ?? ?? ?? ?? 8B C7 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 48 ?? 2B 08 
            C1 F9 ?? 89 8D ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 8A 8D ?? ?? ?? ?? 84 C9 74 ?? 
            80 F9 ?? 75 ?? 80 BD ?? ?? ?? ?? ?? 74 ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 
            50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 
            C0 8B 85 ?? ?? ?? ?? 75 ?? 8B 10 8B 40 ?? 8B 8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B C8 0F 
            84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? E9
        }

        $encrypt_files = {
            68 ?? ?? ?? ?? 83 EC ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8B CC C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C6 85 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? 
            ?? ?? 83 79 ?? ?? C7 41 ?? ?? ?? ?? ?? 72 ?? 8B 01 EB ?? 8B C1 6A ?? C6 00 ?? 8D 85 
            ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 50 68 ?? ?? 
            ?? ?? 51 6A ?? 83 EC ?? C6 45 ?? ?? 8B CC C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 
            C7 41 ?? ?? ?? ?? ?? 83 79 ?? ?? C7 41 ?? ?? ?? ?? ?? 72 ?? 8B 01 EB ?? 8B C1 6A ?? 
            C6 00 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 8B BD ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 47 ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 83 EC ?? 8B CC C7 41 ?? ?? ?? ?? 
            ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 83 79 ?? ?? C7 41 ?? ?? ?? ?? ?? 72 ?? 
            8B 01 EB ?? 8B C1 6A ?? C6 00 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            $encrypt_files
        )
}
