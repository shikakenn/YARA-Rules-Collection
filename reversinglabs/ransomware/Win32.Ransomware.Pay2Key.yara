rule Win32_Ransomware_Pay2Key : tc_detection malicious
{
    meta:
        id = "cAb5WcOSc9nKaaJUxc0np"
        fingerprint = "v1_sha256_2497504f3afc99523cb29e51652a24f4374316d57d4baf5cde8d22e75a425585"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Pay2Key ransomware."
        category = "MALWARE"
        malware = "PAY2KEY"
        mitre_att = "S0556"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Pay2Key"
        tc_detection_factor = 5

    strings:

        $find_files = {
            8B FF 55 8B EC 51 8B 4D ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA 83 C8 ?? 57 8B 7D ??
            41 2B C7 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 53 56 8D 5F ?? 03 D9 6A ?? 53 E8 ?? ??
            ?? ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ??
            FF 75 ?? 2B DF 8D 04 3E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8B 4D ??
            56 E8 ?? ?? ?? ?? 6A ?? 8B F0 E8 ?? ?? ?? ?? 59 8B C6 5E 5B 5F 8B E5 5D C3 33 C0 50
            50 50 50 50 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5
            89 45 ?? 8B 4D ?? 53 8B 5D ?? 56 8B 75 ?? 57 89 B5 ?? ?? ?? ?? EB ?? 8A 01 3C ?? 74
            ?? 3C ?? 74 ?? 3C ?? 74 ?? 51 53 E8 ?? ?? ?? ?? 59 59 8B C8 3B CB 75 ?? 8A 11 80 FA
            ?? 75 ?? 8D 43 ?? 3B C8 74 ?? 56 33 FF 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 33 FF
            80 FA ?? 74 ?? 80 FA ?? 74 ?? 80 FA ?? 74 ?? 8B C7 EB ?? 33 C0 40 0F B6 C0 2B CB 41
            F7 D8 68 ?? ?? ?? ?? 1B C0 23 C1 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 E8 ?? ??
            ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 57 57 57 50 57 53 FF 15 ?? ?? ?? ?? 8B F0 8B 85 ??
            ?? ?? ?? 83 FE ?? 75 ?? 50 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 83 FE ?? 74 ?? 56
            FF 15 ?? ?? ?? ?? 8B C7 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 48 ??
            2B 08 C1 F9 ?? 89 8D ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 8A 8D ?? ?? ?? ?? 84 C9
            74 ?? 80 F9 ?? 75 ?? 80 BD ?? ?? ?? ?? ?? 74 ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ??
            ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ??
            ?? 85 C0 8B 85 ?? ?? ?? ?? 75 ?? 8B 10 8B 40 ?? 8B 8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B
            C8 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4
            ?? E9
        }

        $encrypt_files = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? 53 56 57 A1 ?? ?? ?? ??
            33 C5 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B D9 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??
            8B 43 ?? 2B 43 ?? 75 ?? 8B 75 ?? 8B 45 ?? 8B 4D ?? C7 45 ?? ?? ?? ?? ?? 89 06 89 4E
            ?? 8B 4D ?? 89 4E ?? 8D 4D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ??
            ?? 8B C6 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B E5 5D C2 ?? ?? 83 7B ?? ?? 74
            ?? 8B 45 ?? 2B 45 ?? 50 E8 ?? ?? ?? ?? 8B 75 ?? 8B F8 8B 55 ?? 2B F2 56 52 57 E8 ??
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ??
            56 89 75 ?? E8 ?? ?? ?? ?? 56 57 50 89 45 ?? E8 ?? ?? ?? ?? 8B 75 ?? 8D 45 ?? 83 C4
            ?? 50 56 6A ?? 6A ?? 6A ?? FF 73 ?? FF 15 ?? ?? ?? ?? 8D 4D ?? 85 C0 75 ?? 8B 75 ??
            89 45 ?? 89 45 ?? 89 45 ?? 89 06 89 46 ?? 89 46 ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ??
            ?? ?? 8B C6 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B E5 5D C2 ?? ?? FF 75 ?? E8
            ?? ?? ?? ?? FF 75 ?? 56 8B 75 ?? 56 E8 ?? ?? ?? ?? 8B 7D ?? 83 C4 ?? 8B 4D ?? 8B 45
            ?? C7 45 ?? ?? ?? ?? ?? 89 4F ?? 8D 4D ?? 89 37 89 47 ?? C7 45 ?? ?? ?? ?? ?? C7 45
            ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B C7 8B 4D ?? 64 89 0D ?? ??
            ?? ?? 59 5F 5E 5B 8B E5 5D C2
        }

        $remote_connection_p1 = {
            55 8B EC 83 EC ?? 56 57 6A ?? 8B F2 8B F9 FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 8D 45 ?? C7
            45 ?? ?? ?? ?? ?? 50 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 6A ?? 56 57 FF 15 ?? ?? ?? ??
            8B 75 ?? 8B C8 8B D6 E8 ?? ?? ?? ?? 8B 0E 8B F8 83 F9 ?? 75 ?? 68 ?? ?? ?? ?? 8B CE
            E8 ?? ?? ?? ?? EB ?? 81 F9 ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? EB
            ?? 81 F9 ?? ?? ?? ?? 74 ?? 81 F9 ?? ?? ?? ?? 74 ?? 85 FF 74 ?? 5F 83 C8 ?? 5E 8B E5
            5D C3
        }

        $remote_connection_p2 = {
            55 8B EC 51 53 56 8B F1 57 8B 46 ?? 83 C0 ?? 50 FF 15 ?? ?? ?? ?? 80 7D ?? ?? 6A ??
            74 ?? 8B 4E ?? 6A ?? FF 75 ?? E8 ?? ?? ?? ?? 5F 5E 5B 59 5D C2 ?? ?? 8B 45 ?? 8B 08
            83 F9 ?? 75 ?? 8B 4E ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 5F 5E 5B 59 5D C2 ??
            ?? 8B 45 ?? 8B 7D ?? 57 89 45 ?? 8D 45 ?? 50 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 FF 75
            ?? FF 75 ?? 51 FF 15 ?? ?? ?? ?? 8B D8 FF 15 ?? ?? ?? ?? 83 F8 ?? 75 ?? B8 ?? ?? ??
            ?? EB ?? 3D ?? ?? ?? ?? B9 ?? ?? ?? ?? 0F 44 C1 85 DB 74 ?? 3D ?? ?? ?? ?? 74 ?? FF
            75 ?? 8B 4E ?? 50 57 E8 ?? ?? ?? ?? 5F 5E 5B 59 5D C2 ?? ?? 8B 4E ?? 57 E8 ?? ?? ??
            ?? 5F 5E 5B 59 5D C2
        }

        $remote_connection_p3 = {
            55 8B EC 83 EC ?? 56 57 6A ?? 8B F2 8B F9 FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 45
            ?? C7 45 ?? ?? ?? ?? ?? 50 FF 75 ?? 56 57 FF 15 ?? ?? ?? ?? 8B 75 ?? 8B C8 8B D6 E8
            ?? ?? ?? ?? 8B 0E 8B F8 83 F9 ?? 75 ?? 68 ?? ?? ?? ?? EB ?? 81 F9 ?? ?? ?? ?? 75 ??
            68 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 85 FF 74 ?? 5F 83 C8 ?? 5E 8B E5 5D C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            $encrypt_files
        ) and
        (
            all of ($remote_connection_p*)
        )
}
