rule Win32_Ransomware_TeleCrypt : tc_detection malicious
{
    meta:
        id = "bNh0WN2aIuK3MkqcElR9R"
        fingerprint = "v1_sha256_9d856eae4369cd7ba1d88bd6ef37931e069127e2c05a84a44f5274f681e83fc0"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects TeleCrypt ransomware."
        category = "MALWARE"
        malware = "TELECRYPT"
        tc_detection_type = "Ransomware"
        tc_detection_name = "TeleCrypt"
        tc_detection_factor = 5

    strings:
        $encrypt_file = {
            57 E8 ?? ?? ?? ?? 89 03 EB ?? 6A ?? E8 ?? ?? ?? ?? 89 03 66 83 BB ?? ?? ?? ?? ?? 0F 
            85 ?? ?? ?? ?? 8B 03 50 E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? 66 81 7B ?? ?? ?? 75 ?? E8 ?? 
            ?? ?? ?? 66 89 83 ?? ?? ?? ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 89 83 ?? ?? ?? ?? E9 
            ?? ?? ?? ?? 0F B7 05 ?? ?? ?? ?? 66 89 83 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 43 ?? ?? ?? 
            ?? ?? 6A ?? 68 ?? ?? ?? ?? 52 6A ?? 6A ?? 50 8D 43 ?? 50 E8 ?? ?? ?? ?? 83 F8 ?? 75 
            ?? 66 C7 43 ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 E9 ?? ?? ?? ?? 89 03 66 81 7B ?? ?? ?? 0F 
            85 ?? ?? ?? ?? 66 C7 43 ?? ?? ?? 6A ?? 8B 03 50 E8 ?? ?? ?? ?? 8B F8 83 FF ?? 75 ?? 
            8B C3 E8 ?? ?? ?? ?? 8B F0 E9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 85 FF 7D ?? 33 FF 6A ?? 
            6A ?? 57 8B 03 50 E8 ?? ?? ?? ?? 40 74 ?? 6A ?? 8D 44 24 ?? 50 68 ?? ?? ?? ?? 8D 83 
            ?? ?? ?? ?? 50 8B 03 50 E8 ?? ?? ?? ?? 85 C0 75 ?? 8B C3 E8 ?? ?? ?? ?? 8B F0 E9 ?? 
            ?? ?? ?? F6 43 ?? ?? 74 ?? 83 3C 24 ?? 76 ?? 8B 14 24 4A 85 D2 72 ?? 42 33 FF 8D 83 
            ?? ?? ?? ?? 80 38 ?? 75 ?? 6A ?? 6A ?? 8B C7 2B 44 24 ?? 50 8B 03 50 E8 ?? ?? ?? ?? 
            40 74 ?? 8B 03 50 E8 ?? ?? ?? ?? 85 C0 75 ?? 8B C3 E8 ?? ?? ?? ?? 8B F0 EB ?? 47 40 
            4A 75 ?? 66 83 BB ?? ?? ?? ?? ?? 75 ?? 0F B7 05 ?? ?? ?? ?? 66 89 83 ?? ?? ?? ?? 66 
            81 7B ?? ?? ?? 74 ?? 8B 03 50 E8
        }

        $server_communication = {
            6A ?? 8D 45 ?? 50 8B 45 ?? 8B 80 ?? ?? ?? ?? 33 C9 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 
            ?? 8D 45 ?? 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 55 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? FF 75 ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ?? 
            8B 4D ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 8B 80 ?? ?? ?? ?? 
            33 C9 E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? B2 ?? A1 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 33 DB 8B CB B8 ?? ?? ?? 
            ?? D3 E0 85 F0 74 ?? 8D 45 ?? 8B D3 66 83 C2 ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B 55 ?? A1 ?? ?? ?? ?? 8B 08 FF 51 ?? 43 83 FB ?? 75 ?? A1 ?? ?? 
            ?? ?? 8B 10 FF 52 ?? 8B F0 4E 85 F6 7C ?? 46 33 DB 8D 4D ?? 8B D3 A1 ?? ?? ?? ?? 8B 
            38 FF 57 ?? 8B 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 43 4E 75 ?? A1 ?? ?? ?? ?? 8B 10 
            FF 52 ?? 8B F0 4E 85 F6 7C ?? 46 33 DB 6A ?? 6A ?? 8D 4D ?? 8B D3 A1 ?? ?? ?? ?? 8B 
            38 FF 57 ?? 8B 45 ?? 8B 0D ?? ?? ?? ?? 33 D2 E8 ?? ?? ?? ?? 43 4E 75 ?? 8D 55 ?? B8 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? A1 ?? ?? 
            ?? ?? 8B 08 FF 91 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8B 45 ?? 8B 80 ?? ?? ?? ?? 33 C9 BA 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 55 
            ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 45 ?? BA ?? ?? ?? ?? E8
        }

        $server_communication_1 = {
            55 8B EC 33 C9 51 51 51 51 51 53 8B D8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 6A 
            ?? 8D 45 ?? 50 33 C9 BA ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 8D 45 ?? 
            50 8D 55 ?? 8B 83 ?? ?? ?? ?? 8B 08 FF 91 ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? E8 ?? ?? ?? 
            ?? 8B 4D ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 33 C9 8B 83 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 33 D2 8B 83 ?? ?? ?? ?? 8B 08 FF 91 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 
        }
        
        $exec_payload = {
            55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8B 4D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 
            E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? 
            ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 6A ?? 6A ?? 8D 55 ?? 33 C0 E8 ?? ?? ?? ?? 
            8B 45 ?? E8 ?? ?? ?? ?? 50 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? C3 
        }

        $copy_payload = {
            55 8B EC 6A ?? 6A ?? 6A ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 ?? B8 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? B2 ?? E8 ?? 
            ?? ?? ?? 84 C0 75 ?? A1 ?? ?? ?? ?? 8B 00 E8 ?? ?? ?? ?? 6A ?? 8D 55 ?? B8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 
            8D 55 ?? 33 C0 E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 33 C0 5A 59 
            59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 
        }
        
        $generate_strings_to_encrypt = {
            0F B6 05 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? 
            E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 50 8D 
            85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? 
            ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 B9 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? 
            ?? 0F B6 05 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 
            ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 50 
            8D 85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? 
            ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 B9 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? 
            ?? ?? 0F B6 05 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 
            45 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 
            50 8D 85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 
            ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 B9 
            ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8 ?? 
            ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 
            8B 45 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8
        }

    condition:
        uint16(0) == 0x5A4D and
        (($generate_strings_to_encrypt and $encrypt_file and $server_communication and $exec_payload) or
        ($encrypt_file and $server_communication_1 and $copy_payload))
}
