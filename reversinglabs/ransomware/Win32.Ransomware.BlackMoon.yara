rule Win32_Ransomware_BlackMoon : tc_detection malicious
{
    meta:
        id = "3QAdAZMijN6d9iYfmQKEQy"
        fingerprint = "v1_sha256_428409096a8637978bf2a1efb3238e4ba87715a909693b0cd26c0f689d567a09"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects BlackMoon ransomware."
        category = "MALWARE"
        malware = "BLACKMOON"
        tc_detection_type = "Ransomware"
        tc_detection_name = "BlackMoon"
        tc_detection_factor = 5

    strings:

        $find_files = {
            81 EC ?? ?? ?? ?? 53 8B 9C 24 ?? ?? ?? ?? 55 56 8B 33 57 8B BC 24 ?? ?? ?? ?? 33 ED 
            85 FF 74 ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 76 ?? 85 F6 74 ?? 83 FE ?? 74 ?? 56 FF 
            15 ?? ?? ?? ?? 8D 44 24 ?? 50 57 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 89 33 74 ?? 8B 84 
            24 ?? ?? ?? ?? 85 C0 74 ?? 8B 4C 24 ?? 83 E1 ?? 80 F9 ?? 74 ?? EB ?? 8B 94 24 ?? ?? 
            ?? ?? 8B 44 24 ?? 85 C2 74 ?? BD ?? ?? ?? ?? 85 F6 74 ?? 83 FE ?? 74 ?? 85 ED 75 ?? 
            8B 84 24 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 85 C0 8D 44 24 ?? 50 56 74 ?? FF D7 85 C0 74 
            ?? 8B 4C 24 ?? 83 E1 ?? 80 F9 ?? 75 ?? 8D 54 24 ?? 52 56 FF D7 85 C0 75 ?? 5F 5E 5D 
            33 C0 5B 81 C4 ?? ?? ?? ?? C3 FF D7 85 C0 74 ?? 8B 9C 24 ?? ?? ?? ?? 85 5C 24 ?? 75 
            ?? 8D 4C 24 ?? 51 56 FF D7 85 C0 75 ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C3 8D 54 24 ?? 
            52 E8 ?? ?? ?? ?? 40 50 E8 ?? ?? ?? ?? 8B D0 8D 7C 24 ?? 83 C9 ?? 33 C0 83 C4 ?? F2 
            AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 ?? F3 A5 8B C8 8B C2 83 E1 ?? F3 A4 5F 5E 5D 
            5B 81 C4 ?? ?? ?? ?? C3 
        }

        $encrypt_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            6A ?? 8B 5D ?? 8B 03 85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B 5D ?? 8B 03 85 C0 75 ?? 
            B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? DB 
            45 ?? DD 5D ?? DD 45 ?? DB 45 ?? DD 5D ?? DC 65 ?? DD 5D ?? DD 45 ?? E8 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 6A ?? 50 68 ?? ?? ?? ?? 6A ?? 8B 5D ?? 8B 03 85 C0 75 ?? B8 ?? ?? ?? 
            ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B 45 ?? 50 8B 
            5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 58 89 45 ?? 68 ?? ?? ?? ?? 6A ?? 8B 5D 
            ?? 8B 03 85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8
        }

        $encrypt_files_p2 = {
            83 C4 ?? 89 45 ?? 8B 45 ?? 50 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 58 89 
            45 ?? 68 ?? ?? ?? ?? 6A ?? 8B 5D ?? 8B 03 85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? 
            ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 85 C0 75 ?? B8 ?? ?? ?? 
            ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 
            8B 45 ?? 50 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 58 89 45 ?? 68 ?? ?? ?? 
            ?? 8B 5D ?? FF 33 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 68 ?? ?? ?? ?? 6A 
            ?? 8B 45 ?? 85 C0 75 ?? B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 85 C0 75 ?? 
            B8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 5D ?? 85 
            DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 
            8B 5D ?? 85 DB 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B E5 5D C2
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
