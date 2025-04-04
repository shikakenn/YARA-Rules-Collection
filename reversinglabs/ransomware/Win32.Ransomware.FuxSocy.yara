rule Win32_Ransomware_FuxSocy : tc_detection malicious
{
    meta:
        id = "1WI4EBiOqWfpeC3qMD6Ejq"
        fingerprint = "v1_sha256_8b3c04eb5d60fcc82e47cb8e78da0a98642666546d6799baef24b56926e3aceb"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects FuxSocy ransomware."
        category = "MALWARE"
        malware = "FUXSOCY"
        tc_detection_type = "Ransomware"
        tc_detection_name = "FuxSocy"
        tc_detection_factor = 5

    strings:

        $encrypt_files_1 = {
            83 EC ?? 53 55 57 89 54 24 ?? 8B 54 24 ?? 51 33 DB E8 ?? ?? ?? ?? 8B E8 59 85 ED 0F 
            84 ?? ?? ?? ?? 8B 44 24 ?? 89 5C 24 ?? 89 5C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8B CB E9 
            ?? ?? ?? ?? 53 53 FF 74 24 ?? 41 FF 74 24 ?? BF ?? ?? ?? ?? FF 74 24 ?? 3B C7 0F 42 
            F8 2B C7 89 4C 24 ?? 89 44 24 ?? FF 15 ?? ?? ?? ?? 53 8D 44 24 ?? 50 57 FF 74 24 ?? 
            FF 74 24 ?? FF 15 ?? ?? ?? ?? 57 FF 74 24 ?? 8D 54 24 ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 
            59 59 57 8D 44 24 ?? 50 FF 74 24 ?? 33 C0 39 44 24 ?? 53 0F 94 C0 89 7C 24 ?? 50 53 
            55 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 53 53 FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? FF 15 ?? 
            ?? ?? ?? 53 8D 44 24 ?? 50 57 FF 74 24 ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 01 7C 24 ?? 
            8B 4C 24 ?? 11 5C 24 ?? F6 C1 ?? 75 ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 4C 24 ?? 8B 44 24 
            ?? 85 C0 0F 85 ?? ?? ?? ?? EB ?? 88 5C 24 ?? FF 74 24 ?? 8B 54 24 ?? 8B 4C 24 ?? E8 
            ?? ?? ?? ?? 59 8B 4C 24 ?? 55 89 41 ?? FF 15 ?? ?? ?? ?? 8A 5C 24 ?? 5F 5D 8A C3 5B 
            83 C4 ?? C3
        }

        $encrypt_files_2 = {
            83 EC ?? 53 55 56 8B 74 24 ?? 8B C1 8B 36 57 89 54 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 
            8B F8 33 D2 8D 5F ?? 8B C6 F7 F3 33 C9 85 D2 0F 95 C1 89 54 24 ?? 33 D2 03 C8 89 4C 
            24 ?? 0F AF CF 89 4C 24 ?? E8 ?? ?? ?? ?? 8B E8 89 6C 24 ?? 85 ED 0F 84 ?? ?? ?? ?? 
            33 D2 8B CF E8 ?? ?? ?? ?? 8B F0 85 F6 0F 84 ?? ?? ?? ?? 8B 44 24 ?? 83 64 24 ?? ?? 
            48 89 6C 24 ?? 89 44 24 ?? 74 ?? 53 FF 74 24 ?? 89 5C 24 ?? 56 E8 ?? ?? ?? ?? 83 C4 
            ?? 8D 44 24 ?? 57 50 56 33 C0 50 50 50 FF 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? 
            ?? ?? ?? 33 C9 85 FF 74 ?? 8B 54 24 ?? 8D 6E ?? 03 EF 8A 45 ?? 4D 88 04 11 41 3B CF 
            72 ?? 8B 6C 24 ?? 8B 44 24 ?? 03 44 24 ?? 01 5C 24 ?? 89 44 24 ?? 8B 44 24 ?? 40 89 
            44 24 ?? 3B 44 24 ?? 72 ?? 8B 44 24 ?? 85 C0 0F 45 D8 53 FF 74 24 ?? 89 5C 24 ?? 56 
            E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 57 50 56 6A ?? 6A ?? 6A ?? FF 74 24 ?? FF 15 ?? 
            ?? ?? ?? 8B D8 F7 DB 1A DB 80 E3 ?? 33 C9 85 FF 74 ?? 8B 6C 24 ?? 8D 56 ?? 03 D7 8A 
            02 4A 88 04 29 41 3B CF 72 ?? 8B 6C 24 ?? 8B CE E8 ?? ?? ?? ?? 84 DB 75 ?? 8B CD E8 
            ?? ?? ?? ?? 33 ED EB ?? 32 DB EB ?? 8B 4C 24 ?? 8B 44 24 ?? 89 01 5F 5E 8B C5 5D 5B 
            83 C4 ?? C3 
        }

        $find_files_1 = {
            81 EC ?? ?? ?? ?? 53 56 57 8B BC 24 ?? ?? ?? ?? 8B F2 89 74 24 ?? 8B D9 85 FF 0F 84 
            ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 8B D7 C1 E2 ?? 8B 
            CE E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 
            0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D3 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 84 C0 
            0F 84 ?? ?? ?? ?? 55 68 ?? ?? ?? ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 
            44 24 ?? 50 8D 84 24 ?? ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B E8 
            83 FD ?? 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8B 44 
            24 ?? 83 E0 ?? 74 ?? F6 84 24 ?? ?? ?? ?? ?? 75 ?? 85 C0 75 ?? F6 84 24 ?? ?? ?? ?? 
            ?? 74 ?? 33 F6 85 FF 74 ?? 8B 44 24 ?? FF 34 B0 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 
            C0 75 ?? 46 3B F7 72 ?? EB ?? FF B4 24 ?? ?? ?? ?? 8D 44 24 ?? 50 53 FF 94 24 ?? ?? 
            ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 BC 24 ?? ?? ?? ?? ?? 74 ?? FF B4 24 ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 8B 74 24 ?? F6 44 24 ?? ?? 74 ?? F6 84 24 ?? ?? ?? ?? ?? 74 
            ?? 8D 44 24 ?? 50 8B D3 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 84 C0 74 ?? 83 BC 24 
            ?? ?? ?? ?? ?? 74 ?? FF B4 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 8B 
            D6 FF B4 24 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? 
            ?? FF B4 24 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 50 55 FF 15 ?? ?? ?? 
            ?? 85 C0 0F 85 ?? ?? ?? ?? EB ?? 83 64 24 ?? ?? 55 FF 15 ?? ?? ?? ?? 5D 5F 5E 5B 81 
            C4 ?? ?? ?? ?? C3
        }

        $find_files_2 = {
            81 EC ?? ?? ?? ?? 8D 44 24 ?? 53 55 56 68 ?? ?? ?? ?? 50 8B D9 FF 15 ?? ?? ?? ?? 8B 
            F0 85 F6 0F 84 ?? ?? ?? ?? 8D 6C 24 ?? 8D 6C 75 ?? 33 C0 66 89 44 74 ?? 68 ?? ?? ?? 
            ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 59 E8 ?? ?? ?? ?? 83 C0 ?? 6A ?? 59 66 89 
            45 ?? E8 ?? ?? ?? ?? 83 C0 ?? 66 89 44 74 ?? 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 
            FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? 50 FF 15 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 84 C0 74 ?? 8D 84 24 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 83 64 24 ?? ?? 8D 44 
            24 ?? 50 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 44 24 ?? 50 53 
            FF 15 ?? ?? ?? ?? 5E 5D 5B 81 C4 ?? ?? ?? ?? C3
        }

        $find_files_3 = {
            81 EC ?? ?? ?? ?? 53 55 56 8B D9 57 8B FA 85 DB 74 ?? 33 D2 E8 ?? ?? ?? ?? 8B F0 85 
            F6 0F 84 ?? ?? ?? ?? 57 56 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 
            83 C4 ?? 8B CE E8 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 C6 43 ?? ?? FF 15 ?? ?? ?? ?? 
            0D ?? ?? ?? ?? 50 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 
            ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? EB ?? 57 FF 15 ?? ?? ?? ?? 0D ?? ?? ?? ?? 50 57 FF 
            15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D7 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 84 C0 0F 
            84 ?? ?? ?? ?? 8B B4 24 ?? ?? ?? ?? 80 7E ?? ?? 75 ?? 8B 15 ?? ?? ?? ?? 8D 8C 24 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8D 44 24 ?? 50 8D 84 24 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? 8B E8 83 FD ?? 0F 84 ?? ?? ?? ?? 83 64 24 ?? ?? 6A ?? FF 35 ?? 
            ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 84 C0 
            0F 85 ?? ?? ?? ?? F7 44 24 ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 83 7C 24 ?? ?? 75 ?? 56 
            57 FF 15 ?? ?? ?? ?? 50 8B D7 8B CB E8 ?? ?? ?? ?? 59 59 89 44 24 ?? 85 C0 0F 84 ?? 
            ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 50 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? F6 44 
            24 ?? ?? 74 ?? 80 7E ?? ?? 75 ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 4C 24 ?? 56 FF B4 24 ?? 
            ?? ?? ?? 8D 54 24 ?? E8 ?? ?? ?? ?? 59 59 EB ?? 80 7E ?? ?? 74 ?? 85 DB 74 ?? 83 7C 
            24 ?? ?? 7C ?? 7F ?? 81 7C 24 ?? ?? ?? ?? ?? 72 ?? 80 3E ?? 74 ?? 6A ?? 8D 44 24 ?? 
            50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 56 8D 44 24 ?? 50 FF 74 24 ?? FF 94 24 ?? ?? ?? ?? 
            83 C4 ?? 85 C0 74 ?? 8D 44 24 ?? 50 55 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 55 
            FF 15 ?? ?? ?? ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C3
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($find_files_*)
        ) and 
        (
            all of ($encrypt_files_*)
        )
}
