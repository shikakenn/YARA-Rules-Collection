rule Win32_Ransomware_Rokku : tc_detection malicious
{
    meta:
        id = "3Bj79sUsbyxDvGkZWJMGpe"
        fingerprint = "v1_sha256_fefb342f8a9afac3b40c343b830f334225ff4198d55504846aa855acf5dfc9ba"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Rokku ransomware."
        category = "MALWARE"
        malware = "ROKKU"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Rokku"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 8B E9 C7 44 24 ?? ?? ?? ?? ?? 33 DB 89 6C 24 ?? 
            56 0F 57 C0 66 C7 44 24 ?? ?? ?? 57 66 0F 13 44 24 ?? B2 ?? 88 5C 24 ?? 8B CB 8A C1 
            02 C2 30 44 0C ?? 41 83 F9 ?? 73 ?? 8A 54 24 ?? EB ?? 8B CD 88 5C 24 ?? E8 ?? ?? ?? 
            ?? 8D 54 24 ?? 8B C8 E8 ?? ?? ?? ?? 85 C0 75 ?? 40 E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? 
            ?? FF 15 ?? ?? ?? ?? 51 BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B D6 E8 ?? ?? ?? ?? 59 56 BE 
            ?? ?? ?? ?? BA ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 8D 4C 24 ?? 6A 
            ?? 8B D5 E8 ?? ?? ?? ?? 59 59 85 C0 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 
            C0 0F 84 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 8B C1 8B 94 24 ?? ?? ?? ?? 0B C2 0F 84 ?? 
            ?? ?? ?? 6A ?? 5D 3B D3 77 ?? 81 F9 ?? ?? ?? ?? 76 ?? 2B CD 1B D3 52 51 55 8D 4C 24 
            ?? E8 ?? ?? ?? ?? 83 C4 ?? 3B C5 0F 85 ?? ?? ?? ?? 8B CD 8B C3 8A 90 ?? ?? ?? ?? 49 
            8A B0 ?? ?? ?? ?? 3A D6 75 ?? 40 85 C9 75 ?? 8B CB EB ?? 0F B6 C6 0F B6 CA 2B C8 85 
            C9 0F 84 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8D 44 24 ?? 8B D6 50 B9 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 88 19 41 83 E8 ?? 75 ?? 
            8B 6C 24 ?? 8B 7C 24 ?? 8B 84 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 2B C7 1B CD 3B EB
        }

        $encrypt_files_p2 = {
            7C ?? 7F ?? 81 FF ?? ?? ?? ?? 72 ?? 8B AC 24 ?? ?? ?? ?? 0F 57 C0 8B BC 24 ?? ?? ?? 
            ?? 8B 4C 24 ?? 55 57 66 0F 13 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 59 59 8B 4C 24 ?? 
            3B CB 77 ?? 3B C3 77 ?? 8B F3 EB ?? 3B CB 77 ?? 72 ?? 3D ?? ?? ?? ?? 72 ?? B8 ?? ?? 
            ?? ?? 55 57 50 8D 4C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 85 F6 0F 88 ?? ?? ?? ?? 74 
            ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 56 50 8B D0 E8 ?? ?? ?? ?? 55 57 56 BA ?? ?? ?? ?? 
            8D 4C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 88 ?? ?? ?? ?? 99 03 F8 13 EA E9 ?? ?? 
            ?? ?? 6A ?? 58 89 1D ?? ?? ?? ?? 83 E8 ?? 75 ?? 8B C7 89 1D ?? ?? ?? ?? 0B C5 BE ?? 
            ?? ?? ?? 74 ?? 51 8D 54 24 ?? E8 ?? ?? ?? ?? 59 B9 ?? ?? ?? ?? 3B F1 74 ?? 56 51 BA 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 55 57 BD ?? ?? ?? ?? 8B D1 55 8D 4C 24 ?? E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 0F 88 ?? ?? ?? ?? EB ?? BD ?? ?? ?? ?? 6A ?? 59 8B C1 BA ?? 
            ?? ?? ?? C6 02 ?? 42 83 E8 ?? 75 ?? B8 ?? ?? ?? ?? C6 00 ?? 40 83 E9 ?? 75 ?? 6A ?? 
            58 B9 ?? ?? ?? ?? C6 01 ?? 41 83 E8 ?? 75 ?? C6 06 ?? 46 83 ED ?? 75 ?? 6A ?? 8D 44 
            24 ?? 59 C6 00 ?? 40 83 E9 ?? 75 ?? B1 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? 
            ?? ?? 8B C3 30 4C 04 ?? 40 83 F8 ?? 73 ?? 8A 4C 24 ?? EB ?? 8B 4C 24 ?? 8D 54 24 ?? 
            88 5C 24 ?? E8 ?? ?? ?? ?? 8D 4C 24 ?? 8B F0 E8 ?? ?? ?? ?? 8B 4C 24 ?? 8B D6 E8 ?? 
            ?? ?? ?? 56 E8 ?? ?? ?? ?? 59 33 DB 43 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B C3 EB ?? 8D 4C 
            24 ?? E8 ?? ?? ?? ?? 33 C0 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C3 
        }

        $encrypt_files_p3 = {
            55 8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? 53 55 56 57 6A ?? 5E 56 BF ?? ?? ?? ?? 57 FF 15 
            ?? ?? ?? ?? 51 BB ?? ?? ?? ?? BD ?? ?? ?? ?? 8B D3 8B CD E8 ?? ?? ?? ?? 59 56 57 FF 
            15 ?? ?? ?? ?? 51 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8B C6 C6 07 ?? 47 
            83 E8 ?? 75 ?? BF ?? ?? ?? ?? BA ?? ?? ?? ?? 53 8B CF E8 ?? ?? ?? ?? 59 6A ?? 58 C6 
            03 ?? 43 83 E8 ?? 75 ?? B9 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 3B E9 74 ?? 55 51 8B D6 
            E8 ?? ?? ?? ?? 83 C4 ?? B9 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3B C1 74 ?? 50 51 8B D6 E8 ?? 
            ?? ?? ?? 83 C4 ?? 6A ?? 5B 53 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8D 44 24 ?? B9 ?? ?? 
            ?? ?? 50 51 8B D3 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C4 ?? 3B C8 74 ?? 
            51 50 6A ?? 5A 8B C8 E8 ?? ?? ?? ?? 83 C4 ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B C1 74 
            ?? 50 51 8B D6 E8 ?? ?? ?? ?? 83 C4 ?? B9 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3B C1 74 ?? 50 
            51 6A ?? 5A E8 ?? ?? ?? ?? 83 C4 ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 6A ?? 5B 3B C1 74 
            ?? 50 51 8B D3 E8 ?? ?? ?? ?? 83 C4 ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B C1 74 ?? 50 
            51 6A ?? 5A E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 8B D7 50 8D 4C 24 ?? E8 ?? ?? ?? ?? 
            59 BA ?? ?? ?? ?? 8D 4C 24 ?? 6A ?? 52 E8 ?? ?? ?? ?? 59 59 83 64 24 ?? ?? 83 EB ?? 
            75 ?? 21 9C 24 ?? ?? ?? ?? 8D 44 24 ?? 6A ?? 59 C6 00 ?? 40 83 E9 ?? 75 ?? 8B C6 C6 
            45 ?? ?? 45 83 E8 ?? 75 ?? C6 07 ?? 47 83 EE ?? 75 ?? 33 C0 5F 40 5E 5D 5B 8B E5 5D 
            C3 
        }

        $find_files_p1 = {
            55 8B EC 83 EC ?? 53 56 6A ?? 59 E8 ?? ?? ?? ?? 8B F0 66 C7 45 ?? ?? ?? 33 DB 89 35 
            ?? ?? ?? ?? B1 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B C3 C7 45 ?? ?? ?? ?? 
            ?? 66 C7 45 ?? ?? ?? 02 C8 30 4C 05 ?? 40 83 F8 ?? 73 ?? 8A 4D ?? EB ?? 8D 45 ?? 88 
            5D ?? 50 8D 55 ?? 8B CE E8 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? B0 ?? 59 B1 ?? 88 5D ?? 
            32 C1 88 4D ?? 88 45 ?? 8B CB 0F 11 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            66 C7 45 ?? ?? ?? 88 5D ?? 8A 45 ?? 30 44 0D ?? 41 83 F9 ?? 72 ?? 8B 0D ?? ?? ?? ?? 
            8D 45 ?? 50 8D 55 ?? 88 5D ?? E8 ?? ?? ?? ?? 59 B1 ?? 88 5D ?? B0 ?? 88 4D ?? 32 C1 
            C7 45 ?? ?? ?? ?? ?? 88 45 ?? 8B C3 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 80 44 
            05 ?? ?? 40 83 F8 ?? 72 ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? E8 ?? ?? ?? ?? 59 
            6A ?? 33 C9 C7 45 ?? ?? ?? ?? ?? 5B B0 ?? 88 5D ?? 32 C3 88 4D ?? 88 45 ?? 8B C1 C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 88 4D ?? 80 44 05 ?? ?? 40 83 F8 ?? 72 ?? 8B 
            0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? E8 ?? ?? ?? ?? 59 6A ?? 88 5D ?? B2 ?? 66 C7 45 
            ?? ?? ?? 33 C9 66 C7 45 ?? ?? ?? C6 45 ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 5B 8D 
            04 0A 30 44 0D ?? 41 3B CB 73 ?? 8A 55 ?? EB ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 
            ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 59 6A ?? 33 C9 C6 45 ?? ?? 58 34 ?? 88 4D ?? 88 45
        }

        $find_files_p2 = {
            B2 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? 8D 04 0A 30 44 0D 
            ?? 41 83 F9 ?? 73 ?? 8A 55 ?? EB ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? C6 45 ?? 
            ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 80 F3 ?? C6 45 ?? ?? 88 5D ?? 8D 55 ?? 
            33 DB C6 45 ?? ?? 50 88 5D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 59 59 6A ?? 58 34 ?? C6 45 ?? ?? 88 45 ?? B2 ?? 88 5D ?? 8B CB C7 45 ?? ?? ?? ?? 
            ?? 66 C7 45 ?? ?? ?? 88 5D ?? 8D 04 0A 30 44 0D ?? 41 83 F9 ?? 73 ?? 8A 55 ?? EB ?? 
            8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? 88 5D ?? E8 ?? ?? ?? ?? 59 66 C7 45 ?? ?? ?? 
            8B C3 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 80 44 05 ?? ?? 
            40 83 F8 ?? 72 ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? E8 ?? ?? ?? ?? B0 ?? C6 45 
            ?? ?? 34 ?? 88 5D ?? 59 88 45 ?? B1 ?? C7 45 ?? ?? ?? ?? ?? 8B C3 C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? 88 5D ?? 30 4C 05 ?? 40 83 F8 ?? 73 ?? 8A 
            4D ?? EB ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? 88 5D ?? E8 ?? ?? ?? ?? 0F 28 05 
            ?? ?? ?? ?? 59 66 C7 45 ?? ?? ?? 8B CB 0F 11 45 ?? C7 45 ?? ?? ?? ?? ?? 88 5D ?? 8A 
            45 ?? 30 44 0D ?? 41 83 F9 ?? 72 ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? 88 5D ?? 
            E8 ?? ?? ?? ?? 59 5E 5B 8B E5 5D C3 
        }

        $find_folders = {
            55 8B EC 83 EC ?? 53 56 6A ?? 59 E8 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 33 DB 8B F0 66 
            C7 45 ?? ?? ?? 89 35 ?? ?? ?? ?? 8B CB 0F 11 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 66 C7 45 ?? ?? ?? 88 5D ?? 8A 45 ?? 30 44 0D ?? 41 83 F9 ?? 72 ?? 8D 45 ?? 
            88 5D ?? 50 8D 55 ?? 8B CE E8 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? B0 ?? 59 B1 ?? 88 5D 
            ?? 32 C1 88 4D ?? 88 45 ?? 8B CB 0F 11 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? 66 C7 45 ?? ?? ?? 8A 45 ?? 30 44 0D ?? 41 83 F9 ?? 72 ?? 8B 0D ?? ?? ?? ?? 8D 45 
            ?? 50 8D 55 ?? 88 5D ?? E8 ?? ?? ?? ?? 59 B1 ?? 88 5D ?? B0 ?? 88 4D ?? 32 C1 C7 45 
            ?? ?? ?? ?? ?? 88 45 ?? B2 ?? C7 45 ?? ?? ?? ?? ?? 8B CB 66 C7 45 ?? ?? ?? 88 5D ?? 
            8D 04 0A 30 44 0D ?? 41 83 F9 ?? 73 ?? 8A 55 ?? EB ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 
            8D 55 ?? 88 5D ?? E8 ?? ?? ?? ?? 59 B1 ?? 88 5D ?? B0 ?? 88 4D ?? 32 C1 C7 45 ?? ?? 
            ?? ?? ?? 88 45 ?? 8B C3 C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? 88 5D ?? 80 44 05 ?? 
            ?? 40 83 F8 ?? 72 ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? E8 ?? ?? ?? ?? 59 66 C7 
            45 ?? ?? ?? 8B C3 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? 80 44 
            05 ?? ?? 40 83 F8 ?? 72 ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 55 ?? E8 ?? ?? ?? ?? 59 
            66 C7 45 ?? ?? ?? B1 ?? C7 45 ?? ?? ?? ?? ?? 8B C3 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 66 C7 45 ?? ?? ?? 30 4C 05 ?? 40 83 F8 ?? 73 ?? 8A 4D ?? EB ?? 8B 0D ?? ?? 
            ?? ?? 8D 45 ?? 50 8D 55 ?? 88 5D ?? E8 ?? ?? ?? ?? 59 66 C7 45 ?? ?? ?? B2 ?? C7 45 
            ?? ?? ?? ?? ?? 8B CB C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? 8D 
            04 0A 30 44 0D ?? 41 83 F9 ?? 73 ?? 8A 55 ?? EB ?? 8B 0D ?? ?? ?? ?? 8D 45 ?? 50 8D 
            55 ?? 88 5D ?? E8 ?? ?? ?? ?? 59 5E 5B 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $find_folders and 
            (
                  all of ($find_files_p*)
            ) and 
            (
                  all of ($encrypt_files_p*)
            )
      )
}
