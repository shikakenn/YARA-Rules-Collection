rule Win32_Ransomware_Sherminator : tc_detection malicious
{
    meta:
        id = "4170YgmlaMpIMkJnjM69YW"
        fingerprint = "v1_sha256_22ac61b95f6ca4530e81a23fdd05be93e368647ca7100097a94eae3c6ce3b7d1"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Sherminator ransomware."
        category = "MALWARE"
        malware = "SHERMINATOR"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Sherminator"
        tc_detection_factor = 5

    strings:

        $enum_resources_p1 = {
            55 89 E5 57 53 83 EC ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 44 24 
            ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 89 45 ?? 83 7D ?? 
            ?? 0F 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? C7 44 24 ?? 
            ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 89 44 24 
            ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? 89 54 
            24 ?? 8B 55 ?? 89 54 24 ?? 8D 55 ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 89 
            45 ?? 83 7D ?? ?? 0F 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 ?? 89
        }

        $enum_resources_p2 = { 
            45 ?? 8B 45 ?? C1 E0 ?? 89 C2 8B 45 ?? 01 D0 8B 40 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 
            ?? C1 E0 ?? 89 C2 8B 45 ?? 01 D0 8B 40 ?? 89 04 24 E8 ?? ?? ?? ?? 83 C0 ?? 8B 15 ?? 
            ?? ?? ?? 8B 0D ?? ?? ?? ?? C1 E1 ?? 8D 1C 0A C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? 
            ?? ?? ?? 89 03 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? C1 E2 ?? 01 D0 8B 00 85 C0 0F 84 ?? 
            ?? ?? ?? 8B 45 ?? C1 E0 ?? 89 C2 8B 45 ?? 01 D0 8B 50 ?? A1 ?? ?? ?? ?? 8B 0D ?? ?? 
            ?? ?? C1 E1 ?? 01 C8 8B 00 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 15 
            ?? ?? ?? ?? C1 E2 ?? 01 D0 8B 10 89 D0 B9 ?? ?? ?? ?? 89 C3 B8 ?? ?? ?? ?? 89 DF F2 
            AE 89 C8 F7 D0 83 E8 ?? 01 D0 66 C7 00 ?? ?? A1 ?? ?? ?? ?? 83 C0 ?? A3 ?? ?? ?? ?? 
            8B 45 ?? C1 E0 ?? 89 C2 8B 45 ?? 01 D0 8B 40 ?? 83 E0 ?? 85 C0 74 ?? 8B 45 ?? C1 E0 
            ?? 89 C2 8B 45 ?? 01 D0 89 04 24 E8 ?? ?? ?? ?? EB ?? 90 83 45 ?? ?? 8B 45 ?? 39 45 
            ?? 0F 82 ?? ?? ?? ?? 81 7D ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? 
            ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 90 90 8D 65 ?? 5B 5F 5D C3 
        }

        $encrypt_files_p1 = {
            55 89 E5 57 83 EC ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 C0 ?? C7 44 24 ?? ?? ?? ?? 
            ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 75 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? 
            ?? A1 ?? ?? ?? ?? FF D0 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 
            ?? B9 ?? ?? ?? ?? 89 C2 B8 ?? ?? ?? ?? 89 D7 F2 AE 89 C8 F7 D0 8D 50 ?? 8B 45 ?? 01 
            D0 66 C7 00 ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 
            89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 89 45 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 
            04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 89 55 
            ?? 83 7D ?? ?? 7F ?? 83 7D ?? ?? 78 ?? 83 7D ?? ?? 77 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 
            45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 44 24 
            ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 
            8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 C7 45 ?? ?? ?? ?? ?? DF 6D ?? 
            DD 5D ?? DD 45 ?? DD 05 ?? ?? ?? ?? DF E9 DD D8 76 ?? 8B 45 ?? 89 45 ?? EB ?? C7 45 
            ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 83 
            7D ?? ?? 75 ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC
        }

        $encrypt_files_p2 = { 
            8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF 
            D0 C7 45 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 15 ?? 
            ?? ?? ?? A1 ?? ?? ?? ?? 8D 4D ?? 89 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 54 24 ?? C7 
            44 24 ?? ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 85 C0 75 ?? C7 04 24 ?? 
            ?? ?? ?? A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? 
            ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? 
            ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 C7 04 24 ?? ?? ?? ?? A1 
            ?? ?? ?? ?? FF D0 83 EC ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 
            04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 85 C0 75 ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 
            24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 
            45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 
            ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? 
            ?? ?? 89 45 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 83 
            7D ?? ?? 74 ?? 83 7D ?? ?? 0F 85 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 44 
            24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 44 24 ?? 8B 45 
        }

        $encrypt_files_p3 = { 
            89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 
            ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 
            24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 
            A1 ?? ?? ?? ?? FF D0 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 ?? BA ?? ?? ?? ?? 39 55 ?? 7F ?? 39 55 ?? 7C ?? 39 
            45 ?? 77 ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 44 24 ?? C7 44 24 
            ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 75 ?? 8B 45 ?? 
            89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 89 54 24 ?? 8D 55 ?? 89 54 24 ?? 8B 55 ?? 
            89 54 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 55 ?? 89 54 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 
            04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 8B 55 ?? 89 54 24 ?? 89 44 24 ?? C7 44 
            24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? BA ?? ?? ?? ?? 29 45 ?? 
            19 55 ?? 83 7D ?? ?? 0F 8F ?? ?? ?? ?? 83 7D ?? ?? 78 ?? 83 7D ?? ?? 0F 87 ?? ?? ?? 
            ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 
            24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? 
            ?? FF D0 83 EC ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 
        }

        $find_files_p1 = {
            55 89 E5 57 53 81 EC ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 C0 ?? C7 44 24 
            ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 75 ?? 8B 45 ?? 89 04 24 
            E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 44 
            24 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? B9 ?? ?? ?? ?? 89 C2 B8 ?? ?? ?? ?? 
            89 D7 F2 AE 89 C8 F7 D0 8D 50 ?? 8B 45 ?? 01 D0 C7 00 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 89 45 ?? 83 7D ?? ?? 0F 
            84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 E0 ?? 85 C0 0F 84 ?? ?? ?? ?? 0F B6 95 ?? ?? ?? 
            ?? 0F B6 05 ?? ?? ?? ?? 0F B6 D2 0F B6 C0 29 C2 89 D0 85 C0 0F 84 ?? ?? ?? ?? C7 44 
            24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 04 24 E8 ?? 
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 
            89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 
            E0 ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 C3 8D 85 ?? ?? ?? 
            ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? 01 D8 83 C0 ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24
        }

        $find_files_p2 = { 
            E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 
            89 04 24 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 E8 
            ?? ?? ?? ?? 8B 45 ?? B9 ?? ?? ?? ?? 89 C2 B8 ?? ?? ?? ?? 89 D7 F2 AE 89 C8 F7 D0 8D 
            50 ?? 8B 45 ?? 01 D0 66 C7 00 ?? ?? A1 ?? ?? ?? ?? 8B 55 ?? 89 54 24 ?? 89 44 24 ?? 
            C7 04 24 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 E9 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? 
            ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 
            0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 04 24 E8 ?? 
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 
        }

        $find_files_p3 = {
            89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? 
            ?? 85 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 04 
            24 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? C7 
            44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? 89 04 
            24 E8 ?? ?? ?? ?? 89 C3 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 04 24 E8 ?? ?? ?? ?? 01 D8 83 
            C0 ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 8B 
            45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 83 C0 ?? 89 44 
            24 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 55 ?? 89 54 24 ?? 89 44 24 
            ?? C7 04 24 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 EB ?? 90 EB ?? 90 EB ?? 90 EB ?? 90 EB 
            ?? 90 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 
            85 C0 0F 85 ?? ?? ?? ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 
            04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($enum_resources_p*)
        ) and 
        (
            all of ($find_files_p*)
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
