rule Win32_Ransomware_Avaddon : tc_detection malicious
{
    meta:
        id = "2N9RMk6o0wJCAYemELvk3X"
        fingerprint = "v1_sha256_1b2c449d5bad02dd06cb4a980fcca1feaf02b1d8127096bb39deecbc544272a6"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Avaddon ransomware."
        category = "MALWARE"
        malware = "AVADDON"
        mitre_att = "S0640"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Avaddon"
        tc_detection_factor = 5

    strings:

        $find_files = {
            8B FF 55 8B EC 51 8B 4D ?? 53 57 33 DB 8D 51 ?? 66 8B 01 83 C1 ?? 66 3B C3 75 ?? 8B 
            7D ?? 2B CA D1 F9 8B C7 41 F7 D0 89 4D ?? 3B C8 76 ?? 6A ?? 58 5F 5B C9 C3 56 8D 5F 
            ?? 03 D9 6A ?? 53 E8 ?? ?? ?? ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? 
            ?? ?? 83 C4 ?? 85 C0 75 ?? FF 75 ?? 2B DF 8D 04 7E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 
            C4 ?? 85 C0 75 ?? 8B 7D ?? 8B CF E8 ?? ?? ?? ?? 8B D8 85 DB 74 ?? 56 E8 ?? ?? ?? ?? 
            59 EB ?? 8B 47 ?? 89 30 83 47 ?? ?? 33 DB 6A ?? E8 ?? ?? ?? ?? 59 8B C3 5E EB ?? 33 
            C0 50 50 50 50 50 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 8B 55 ?? 8B 4D ?? 53 8B 5D ?? 89 8D ?? ?? ?? ?? 56 57 3B D3 74 ?? 0F 
            B7 02 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 84 C0 75 ?? 83 EA ?? 3B D3 75 ?? 8B 8D ?? 
            ?? ?? ?? 0F B7 32 83 FE ?? 75 ?? 8D 43 ?? 3B D0 74 ?? 51 33 FF 57 57 53 E8 ?? ?? ?? 
            ?? 83 C4 ?? E9 ?? ?? ?? ?? 56 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 2B D3 0F B6 C0 D1 FA 
            42 F7 D8 1B C0 33 FF 57 57 23 C2 57 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 53 FF 
            15 ?? ?? ?? ?? 8B F0 8B 85 ?? ?? ?? ?? 83 FE ?? 75 ?? 50 57 57 53 E8 ?? ?? ?? ?? 83 
            C4 ?? 8B F8 E9 ?? ?? ?? ?? 8B 48 ?? 2B 08 C1 F9 ?? 6A ?? 89 8D ?? ?? ?? ?? 59 66 39 
            8D ?? ?? ?? ?? 75 ?? 66 39 BD ?? ?? ?? ?? 74 ?? 66 39 8D ?? ?? ?? ?? 75 ?? 66 39 BD 
            ?? ?? ?? ?? 74 ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 6A ?? 85 C0 8B 85 ?? ?? ?? 
            ?? 59 75 ?? 8B 10 8B 40 ?? 8B 8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B C8 74 ?? 68 ?? ?? ?? 
            ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 8B F8 56 FF 15 ?? ?? ?? 
            ?? 8B C7 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? C9 C3 
        }

        $encrypt_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 8B 45 ?? 8B 
            7D ?? 85 C0 0F 84 ?? ?? ?? ?? 83 FF ?? 0F 84 ?? ?? ?? ?? 6A ?? 8D 4D ?? C7 45 ?? ?? 
            ?? ?? ?? 51 6A ?? 6A ?? 6A ?? 6A ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84
        }

        $encrypt_files_p2 = {
            6A ?? 8D 45 ?? 0F 57 C0 50 66 0F 13 45 ?? FF 75 ?? FF 75 ?? 57 FF 15 ?? ?? ?? ?? 85 
            C0 0F 84 ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? 6A ?? 51 8D 45 ?? 0F 43 45 ?? 68 ?? ?? ?? 
            ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 FF 75 ?? FF 75 
            ?? 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 33 F6 39 75 ?? 0F 86 ?? ?? ?? ?? 83 
            7D ?? ?? 8D 45 ?? 8D 4D ?? 0F 43 45 ?? 83 7D ?? ?? 68 ?? ?? ?? ?? 0F 43 4D ?? 03 C6 
            50 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? 8D 45 ?? 0F 
            43 45 ?? 53 51 50 6A ?? 6A ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? 
            ?? 83 7D ?? ?? 8D 4D ?? 6A ?? 51 8D 45 ?? 0F 43 45 ?? 53 50 57 FF 15 ?? ?? ?? ?? 85 
            C0 0F 84 ?? ?? ?? ?? 81 C6 ?? ?? ?? ?? 3B 75 ?? 0F 82 ?? ?? ?? ?? 83 7D ?? ?? 74
        }

        $encrypt_files_p3 = {
            8B 45 ?? 89 45 ?? 8B 45 ?? 6A ?? 89 45 ?? 8D 45 ?? 50 51 52 57 89 55 ?? 89 4D ?? FF 
            15 ?? ?? ?? ?? 85 C0 74 ?? 8B 9D ?? ?? ?? ?? 83 7B ?? ?? 8D 43 ?? 72 ?? 8B 00 6A ?? 
            8D 4D ?? 51 FF 73 ?? 50 57 FF D6 85 C0 74 ?? 8B 4B ?? 39 4D ?? 75 ?? 8B 45 ?? 89 85 
            ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 6A ?? 89 45 ?? 8D 45 ?? 50 6A ?? 8D 85 ?? ?? 
            ?? ?? 89 4D ?? 50 57 C7 45 ?? ?? ?? ?? ?? FF D6 85 C0 74 ?? 83 7D ?? ?? 75 ?? B3 ?? 
            EB ?? 32 DB 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 
            ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 
            81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8A C3 EB ?? 32 C0 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D 
            ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C2
        }

        $remote_connection_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B 45 ?? 33 C9 8B 75 ?? 89 85 ?? 
            ?? ?? ?? 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? 66 89 8D ?? ?? ?? ?? 89 4D ?? 39 4E ?? 0F 84 ?? ?? ?? ?? 66 39 4E ?? 0F 86 ?? ?? 
            ?? ?? 39 4E ?? 0F 84 ?? ?? ?? ?? 39 4E ?? 0F 84 ?? ?? ?? ?? 8B 06 8D 8D ?? ?? ?? ?? 
            8B 7E ?? BA ?? ?? ?? ?? 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 78 ?? ?? 72 ?? 8B 00 6A 
            ?? 6A ?? 57 FF B5 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B F8 89 BD ?? 
            ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? 
            ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 
            89 85 ?? ?? ?? ?? 85 FF 0F 84 ?? ?? ?? ?? 83 7E ?? ?? 8D 46 ?? 0F B7 4E ?? 72 ?? 8B
        }

        $remote_connection_p2 = { 
            00 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 51 50 57 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? 
            ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 7E ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B D0 83 7A ?? ?? 72 ?? 8B 12 83 7E ?? ?? 8D 4E ?? 72 ?? 8B 09 83 7E ?? ?? 8D 46 ?? 
            72 ?? 8B 00 6A ?? 57 6A ?? 6A ?? 52 51 50 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 95 
            ?? ?? ?? ?? 8B F8 89 BD ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? 
            ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 
            ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 85 FF 0F 84 ?? ?? ?? ?? 8B 46 ?? 85 C0 
            75 ?? 50 50 50 50 57 FF 15 ?? ?? ?? ?? EB ?? 83 C6 ?? 83 7E ?? ?? 72 ?? 8B 36 50 56 
            6A ?? 6A ?? 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84
        }

        $enum_resources_p1 = {
            33 D2 89 7D ?? 89 7D ?? 89 75 ?? 89 45 ?? 89 45 ?? 89 4D ?? 89 55 ?? 89 55 ?? 39 56 
            ?? 0F 84 ?? ?? ?? ?? 89 55 ?? 89 55 ?? 89 55 ?? 89 55 ?? 83 7E ?? ?? 8B C6 72 ?? 8B 
            06 8D 4D ?? 51 8D 4D ?? 51 8D 4D ?? 51 6A ?? 8D 4D ?? 51 6A ?? 50 FF 15 ?? ?? ?? ?? 
            89 45 ?? 85 C0 74 ?? 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8B 45 ?? 89 45 ?? 
            C7 45 ?? ?? ?? ?? ?? 0F 82
        }

        $enum_resources_p2 = {
            8D 4D ?? D1 F8 50 52 E8 ?? ?? ?? ?? 8B 7D ?? 8D 4D ?? 8B 75 ?? 83 FF ?? 8B 55 ?? 6A 
            ?? 68 ?? ?? ?? ?? 0F 43 CE 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 
            8B 7D ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 33 C0 8B 75 ?? 66 89 85 ?? ?? ?? ?? 83 CE ?? 
            8B 47 ?? 83 C0 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 
            75 ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7F ?? 
            ?? 8B C7 72 ?? 8B 07 FF 77 ?? 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? E8
        }

        $enum_resources_p3 = {
            53 8B DC 83 EC ?? 83 E4 ?? 83 C4 ?? 55 8B 6B ?? 89 6C 24 ?? 8B EC 6A ?? 68 ?? ?? ?? 
            ?? 64 A1 ?? ?? ?? ?? 50 53 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 57 50 8D 45 ?? 
            64 A3 ?? ?? ?? ?? 8B 43 ?? 8D 4D ?? 89 45 ?? 89 45 ?? 66 8B 43 ?? 6A ?? 68 ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 
            8D 4D ?? 8D 45 ?? 0F 43 45 ?? 51 50 8D 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 7D ?? 8D 45 ?? 
            8B 75 ?? 8D 4D ?? 8B 55 ?? 83 FF ?? 0F 43 45 ?? 0F 43 CA 8D 04 70 89 45 ?? 8D 45 ?? 
            0F 43 45 ?? 8D 04 70 3B C8 74 ?? 66 83 39 ?? 74 ?? 83 C1 ?? 3B C8 75 ?? 3B C8 74 ?? 
            8D 51 ?? 3B D0 74
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            all of ($enum_resources_p*)
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            all of ($remote_connection_p*)
        )
}
