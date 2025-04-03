rule Win32_Ransomware_RetMyData : tc_detection malicious
{
    meta:
        id = "sLmFr7mEbOCT9XJQnzPOL"
        fingerprint = "v1_sha256_54ce38d75e9ab82a77b9c338f75e180e19ac745f149289c7478a4aa3b44d70fd"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects RetMyData ransomware."
        category = "MALWARE"
        malware = "RETMYDATA"
        tc_detection_type = "Ransomware"
        tc_detection_name = "RetMyData"
        tc_detection_factor = 5

    strings:

        $find_files = {
            55 89 E5 57 56 53 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 29 C4 8D 9D ?? ?? ?? ?? 8B 04 04 
            C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 89 44 24 ?? 89 C7 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            89 1C 24 89 44 24 ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 40 51 51 0F 84 ?? ?? ?? ?? 8D 
            B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 85 
            C0 74 ?? C7 44 24 ?? ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 85 C0 74 ?? F6 85 ?? ?? ?? 
            ?? ?? 89 74 24 ?? 89 7C 24 ?? 74 ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 
            89 D8 E8 ?? ?? ?? ?? EB ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? BA ?? ?? 
            ?? ?? 89 D8 E8 ?? ?? ?? ?? 85 C0 75 ?? 89 D8 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 44 
            24 ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 52 52 0F 85 ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 50 8D 65 ?? 5B 5E 5F 5D C3 55 BA ?? ?? ?? ?? 89 
            E5 53 51 89 C3 E8 ?? ?? ?? ?? 48 74 ?? 5A 89 D8 5B 5D E9 ?? ?? ?? ?? 58 5B 5D C3 
        }

        $enum_resources = {
            55 89 E5 57 56 53 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 29 C4 8D 95 ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? 8B 04 04 C7 44 24 ?? ?? ?? ?? ?? 89 54 24 ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 04 24 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 
            83 EC ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 31 F6 89 
            44 24 ?? 8D 85 ?? ?? ?? ?? 89 5C 24 ?? 89 44 24 ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? 
            ?? ?? ?? 83 EC ?? 3B B5 ?? ?? ?? ?? 7D ?? 83 7B ?? ?? 75 ?? 8B 43 ?? C7 44 24 ?? ?? 
            ?? ?? ?? 89 3C 24 89 44 24 ?? E8 ?? ?? ?? ?? 89 F8 E8 ?? ?? ?? ?? 89 D8 46 83 C3 ?? 
            E8 ?? ?? ?? ?? EB ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 50 8D 65 ?? 5B 5E 5F 
            5D C3 
        }

        $encrypt_files = {
            55 89 E5 57 56 53 89 C3 81 EC ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 
            C0 89 C2 A3 ?? ?? ?? ?? 75 ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 31 
            C0 89 D7 F3 AB 85 DB 75 ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 
            ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 89 5C 24 ?? 8D 9D ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 89 3C 
            24 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 7C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 
            24 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 5C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 34 
            24 E8 ?? ?? ?? ?? 89 74 24 ?? 89 3C 24 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? C7 44 
            24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 EC 
            ?? 83 F8 ?? 89 C3 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 89 7C 24 ?? 89 34 24 EB ?? 8D 
            BD ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 7C 24 ?? C7 44 24 ?? ?? ?? 
            ?? ?? 89 1C 24 89 44 24 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 EC ?? 85 C0 75 ?? 89 
            1C 24 E8 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 
            ?? ?? ?? ?? EB ?? F7 D8 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? 
            89 1C 24 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 EC ?? BA ?? ?? ?? ?? C7 04 24 ?? ?? ?? 
            ?? B8 ?? ?? ?? ?? 89 F1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 
            74 24 ?? 89 1C 24 89 44 24 ?? 8B 85 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 83 EC ?? 
            FF 8D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $enum_resources
        ) and
        (
            $find_files
        ) and
        (
            $encrypt_files
        )
}
