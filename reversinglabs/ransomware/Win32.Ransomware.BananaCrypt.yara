rule Win32_Ransomware_BananaCrypt : tc_detection malicious
{
    meta:
        id = "33UPYGBZ0sifPMFjpg21qP"
        fingerprint = "v1_sha256_6bde4430e438947b0d7f10c4de11216929ec03af81b3d74f8b7bb8ed134d08d2"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects BananaCrypt ransomware."
        category = "MALWARE"
        malware = "BANANACRYPT"
        tc_detection_type = "Ransomware"
        tc_detection_name = "BananaCrypt"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            55 89 E5 57 56 53 89 C3 81 EC ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8B 55 ?? 89 8D ?? ?? ?? 
            ?? 85 D2 74 ?? 8B 45 ?? 85 C0 0F 85 ?? ?? ?? ?? 31 F6 0F B6 13 84 D2 0F 84 ?? ?? ?? 
            ?? 8D 43 ?? 88 95 ?? ?? ?? ?? 8D 8B ?? ?? ?? ?? 8D BD ?? ?? ?? ?? EB ?? 83 C0 ?? 83 
            C7 ?? 88 57 ?? 39 C1 74 ?? 0F B6 10 84 D2 75 ?? 89 BD ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            C6 00 ?? 89 1C 24 E8 ?? ?? ?? ?? 85 C0 89 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 F0 84 
            C0 0F 85 ?? ?? ?? ?? 8D 5D ?? 8D 76 ?? 8D BC 27 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 
            24 E8 ?? ?? ?? ?? 85 C0 89 C6 0F 84 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 
            39 F9 89 C8 76 ?? 0F B6 41 ?? 89 CF 3C ?? 0F 95 C1 3C ?? 0F 95 C2 84 D1 0F 84 ?? ?? 
            ?? ?? 3C ?? 0F 84 ?? ?? ?? ?? 8D 47 ?? C6 07 ?? 8D 7E ?? 39 D8 89 BD ?? ?? ?? ?? 73 
            ?? 0F B6 56 ?? 84 D2 74 ?? 89 F9 8B BD ?? ?? ?? ?? EB ?? 90 0F B6 11 84 D2 74 ?? 83 
            C0 ?? 83 C1 ?? 88 50 ?? 39 D8 75 ?? 89 BD ?? ?? ?? ?? C6 00 ?? 8D 85 ?? ?? ?? ?? 31 
            FF 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 C2 74 ?? 80 38 ?? 74 ?? 8B 85 ?? ?? ?? ?? 66 90 
            83 C7 ?? 80 3C 3A ?? 75 ?? 89 85 ?? ?? ?? ?? 89 54 24 ?? C7 04 24 ?? ?? ?? ?? 89 95 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 46 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 3D ?? ?? ?? ?? 8B 95 
            ?? ?? ?? ?? 74 ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 7C 24 ?? 89 14 24 89
        }

        $encrypt_files_p2 = {
            44 24 ?? 8B 85 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? C7 04 
            24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 8D 85 ?? ?? ?? ?? 89 F1 89 04 24 E8 ?? ?? ?? ?? 
            83 EC ?? 89 F1 E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 89 F1 E8 ?? ?? ?? ?? 89 C7 8D 
            40 ?? 83 F8 ?? 76 ?? 89 F1 83 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 F1 E8 ?? ?? ?? ?? 
            89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 3C 24 89 44 24 ?? E8 ?? ?? ?? ?? 89 F1 E8 ?? 
            ?? ?? ?? 89 F1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 
            ?? ?? ?? ?? 89 F1 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 89 
            F1 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 
            B5 ?? ?? ?? ?? BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A6 0F 84 ?? ?? ?? ?? 8B B5 ?? ?? ?? 
            ?? BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A6 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 8D ?? ?? ?? ?? 
            8B 95 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 
            ?? ?? ?? ?? 8D 74 26 ?? 8B 85 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 
            E8 ?? ?? ?? ?? 8D 65 ?? B8 ?? ?? ?? ?? 5B 5E 5F 5D C3 8B 45 ?? 89 1C 24 89 44 24 ?? 
            8B 45 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 89 C6 E9 ?? ?? ?? ?? 8D 65 ?? 31 C0 5B 5E 5F 5D 
            C3 8D 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? E9
        }

        $find_files_p1 = {
            8D 4C 24 ?? 83 E4 ?? FF 71 ?? 55 89 E5 57 56 53 51 81 EC ?? ?? ?? ?? 8B 31 8B 79 ?? 
            E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 FE ?? 7E ?? 89 74 24 ?? C7 04 
            24 ?? ?? ?? ?? 31 DB E8 ?? ?? ?? ?? 8B 04 9F 89 5C 24 ?? 83 C3 ?? C7 04 24 ?? ?? ?? 
            ?? 89 44 24 ?? E8 ?? ?? ?? ?? 39 DE 75 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 47 ?? 89 04 24 
            E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 89 
            44 24 ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D BD ?? 
            ?? ?? ?? F3 A5 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 04 24 C7 85
        }

        $find_files_p2 = { 
            8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ??
            8D 44 03 ?? 89 04 24 E8 ?? ?? ?? ?? 89 C3 8B 85 ?? ?? ?? ?? 89 1C 24 89 44 24 ?? E8
            ?? ?? ?? ?? 89 DA 8B 0A 83 C2 ?? 8D 81 ?? ?? ?? ?? F7 D1 21 C8 25 ?? ?? ?? ?? 74 ??
            A9 ?? ?? ?? ?? 74 ?? 89 C1 00 C1 83 DA ?? C7 02 ?? ?? ?? ?? C7 42 ?? ?? ?? ?? ?? C7
            42 ?? ?? ?? ?? ?? C7 42 ?? ?? ?? ?? ?? C7 42 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 84 C0 74 ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 65 ?? 31 C0 59 5B 5E
            5F 5D 8D 61 ?? C3 C1 E8 ?? 83 C2 ?? EB ?? 8D 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? B9 ??
            ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D BD ?? ?? ?? ?? BE ?? ?? ?? ?? 89 04 24 B8 ?? ??
            ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? B9 ?? ?? ?? ?? C7 44 24 ??
            ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29
            F9 89 85 ?? ?? ?? ?? A1 ?? ?? ?? ?? 29 CE 81 C1 ?? ?? ?? ?? C1 E9 ?? 89 45 ?? F3
        }

        $find_files_p3 = { 
            A5 89 1C 24 E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? 
            ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C6 74 ?? 89 44 24 ?? C7 44 24 ?? ?? 
            ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 34 24 E8 ?? 
            ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 
            ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 04 
            24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 
            44 24 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 85 C0 89 C6 0F 84 ?? ?? ?? ?? 89 44 24 
            ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? 
            ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 
            44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? E9
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            all of ($encrypt_files_p*)
        )
}
