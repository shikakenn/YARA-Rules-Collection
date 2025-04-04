rule Win32_Ransomware_Atlas : tc_detection malicious
{
    meta:
        id = "4GnMYl0DKWa0LZdb4FeAT2"
        fingerprint = "v1_sha256_1486f931ec096a00d913de0568ddd8aa5a091256445bc28aba90e3e194ebd045"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Atlas ransomware."
        category = "MALWARE"
        malware = "ATLAS"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Atlas"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            8B 74 24 ?? 8B 3D ?? ?? ?? ?? 8D 4C 24 ?? 6A ?? 51 8D 94 24 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 52 56 FF D7 8B 94 24 ?? ?? ?? ?? 8D 44 24 ?? 8D 8C 24 ?? ?? ?? ?? 50 8B 84 24 ?? 
            ?? ?? ?? 51 52 50 E8 ?? ?? ?? ?? 8B 54 24 ?? 83 C4 ?? 8D 4C 24 ?? 8D 84 24 ?? ?? ?? 
            ?? 6A ?? 51 8B 4C 24 ?? 52 50 51 FF 15 ?? ?? ?? ?? 8D 54 24 ?? 6A ?? 52 55 53 56 FF 
            D7 8B 7C 24 ?? 33 C9 3B FD 89 4C 24 ?? 0F 85 ?? ?? ?? ?? EB ?? 8B 4C 24 ?? 33 F6 8A 
            84 34 ?? ?? ?? ?? 02 C1 F6 E9 88 44 34 ?? 8A 84 34 ?? ?? ?? ?? 02 C1 F6 E9 88 44 34 
            ?? 46 83 FE ?? 7C ?? 8B 74 24 ?? 57 56 8D 44 24 ?? 53 8D 8C 24 ?? ?? ?? ?? 50 51 E8 
            ?? ?? ?? ?? 8B 54 24 ?? 8D 84 24 ?? ?? ?? ?? 52 53 56 8D 8C 24 ?? ?? ?? ?? 50 51 E8 
            ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 83 C4 ?? 8D 54 24 ?? 6A ?? 52 50 53 51 FF 15 ?? 
            ?? ?? ?? 8B 44 24 ?? 8D 54 24 ?? 6A ?? 52 55 53 50 FF 15 ?? ?? ?? ?? 8B 4C 24 ?? 8B 
            7C 24 ?? 41 3B FD 89 4C 24 ?? 0F 84 ?? ?? ?? ?? 8B 74 24 ?? 85 FF 74 ?? 8B 54 24 ?? 
            8D 4C 24 ?? 6A ?? 51 57 53 52 FF 15 ?? ?? ?? ?? 56 8B 35 ?? ?? ?? ?? FF D6 8B 44 24 
            ?? 50 FF D6 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 53 FF D6 8B 4C 24 ?? 68 ?? ?? ?? 
            ?? 6A ?? 51 FF D6 5F 5E 5D 33 C0 5B 81 C4 ?? ?? ?? ?? C3 
        }

        $remote_server_1 = {
            68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 33 F6 33 C9 8D 94 24 ?? ?? ?? ?? 8A 0C 2E 
            8D 84 24 ?? ?? ?? ?? 51 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 46 81 FE ?? ?? 
            ?? ?? 7C ?? 8D 8C 24 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 52 E8 ?? ?? 
            ?? ?? 83 C4 ?? 33 F6 33 C0 8D 8C 24 ?? ?? ?? ?? 8A 04 1E 8D 94 24 ?? ?? ?? ?? 50 51 
            68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 46 81 FE ?? ?? ?? ?? 7C ?? 8D 84 24 ?? ?? 
            ?? ?? 8D BC 24 ?? ?? ?? ?? 50 83 C9 ?? 33 C0 33 F6 F2 AE F7 D1 49 51 8D 8C 24 ?? ?? 
            ?? ?? 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 83 FE ?? 
            0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 46 FF 15 ?? ?? ?? ?? 8D BC 24 ?? ?? ?? ?? 83 C9 ?? 
            33 C0 8D 94 24 ?? ?? ?? ?? F2 AE F7 D1 49 52 8D 84 24 ?? ?? ?? ?? 51 50 68 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? BE ?? ?? ?? ?? 8D 84 24 ?? ?? 
            ?? ?? 8A 10 8A 1E 8A CA 3A D3 75 ?? 84 C9 74 ?? 8A 50 ?? 8A 5E ?? 8A CA 3A D3 75 ?? 
            83 C0 ?? 83 C6 ?? 84 C9 75 ?? 33 C0 EB 
        }

        $remote_server_2 = {
            68 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? 8D 8C 24 ?? ?? ?? ?? BB ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 51 2B D8 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 52 03 D8 E8 ?? ?? ?? ?? 8B CB 8B F0 8B C1 83 C6 ?? 8D BC 24 ?? ?? ?? ?? 83 C4 
            ?? C1 E9 ?? F3 A5 8B C8 68 ?? ?? ?? ?? 83 E1 ?? 68 ?? ?? ?? ?? F3 A4 8D 8C 24 ?? ?? 
            ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 94 24 ?? ?? ?? ?? BB 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 2B D8 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? 
            ?? ?? ?? 03 D8 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B CB 8B F0 8B 
            D1 BF ?? ?? ?? ?? C1 E9 ?? F3 A5 83 C4 ?? 8B CA 83 E1 ?? 8D 84 24 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? F3 A4 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            BB ?? ?? ?? ?? 2B D8 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 03 D8 E8 ?? 
            ?? ?? ?? 8B CB 8B F0 8B C1 83 C6 ?? BF ?? ?? ?? ?? 68 ?? ?? ?? ?? C1 E9 ?? F3 A5 8B 
            C8 68 ?? ?? ?? ?? 83 E1 ?? F3 A4 E8 ?? ?? ?? ?? 8D BC 24 ?? ?? ?? ?? 83 C9 ?? 33 C0 
            83 C4 ?? F2 AE F7 D1 49 83 F9 ?? 0F 82 ?? ?? ?? ?? 33 F6 8D BC 24 ?? ?? ?? ?? 8D 8C 
            34 ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 46 83 C7 ?? 81 FE ?? ?? 
            ?? ?? 72 ?? 8B 3D ?? ?? ?? ?? FF D7 8D 94 24 ?? ?? ?? ?? 56 52 8B E8 E8 ?? ?? ?? ?? 
            83 C4 ?? FF D7 8B F0 8D 44 24 ?? 50 2B F5 C7 44 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 
            4C 24 ?? 8D 94 24 ?? ?? ?? ?? 51 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 
            8D 84 24 ?? ?? ?? ?? 8D BC 24 ?? ?? ?? ?? 50 83 C9 ?? 33 C0 F2 AE F7 D1 49 51 8D 8C 
            24 ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 
        }

        $send_post_packet = {
            68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 8B F0 83 
            FE ?? 89 75 ?? 75 ?? 50 E8 ?? ?? ?? ?? 33 C0 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 
            8B E5 5D C3 6A ?? 66 C7 45 ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 ?? 66 89 45 ?? 52 E8 ?? ?? 
            ?? ?? 89 45 ?? 8D 45 ?? 6A ?? 50 56 E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? 56 E8 ?? ?? ?? ?? 
            33 C0 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 8D BD ?? ?? ?? ?? 83 C9 ?? 
            33 C0 6A ?? F2 AE F7 D1 49 51 8D 8D ?? ?? ?? ?? 51 56 E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? 
            56 E8 ?? ?? ?? ?? 33 C0 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 
        }

        $send_get_request = {
            68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 8B D8 83 
            FB ?? 75 ?? 68 ?? ?? ?? ?? 6A ?? 55 FF 15 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 5F 5E 5D 33 
            C0 5B 81 C4 ?? ?? ?? ?? C3 6A ?? 66 C7 44 24 ?? ?? ?? E8 ?? ?? ?? ?? 8D 54 24 ?? 66 
            89 44 24 ?? 52 E8 ?? ?? ?? ?? 89 44 24 ?? 8D 44 24 ?? 6A ?? 50 53 E8 ?? ?? ?? ?? 83 
            F8 ?? 75 ?? 68 ?? ?? ?? ?? 6A ?? 55 FF 15 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 5F 5E 5D 33 
            C0 5B 81 C4 ?? ?? ?? ?? C3 8B FD 83 C9 ?? 33 C0 6A ?? F2 AE F7 D1 49 51 55 53 E8 ?? 
            ?? ?? ?? 83 F8 ?? 75 ?? 68 ?? ?? ?? ?? 6A ?? 55 FF 15 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 
            5F 5E 5D 33 C0 5B 81 C4 ?? ?? ?? ?? C3 
        }        
    condition:
        uint16(0) == 0x5A4D and $encrypt_files and $remote_server_1 and $remote_server_2 and
        $send_post_packet and $send_get_request
}
