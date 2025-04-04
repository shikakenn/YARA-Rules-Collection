rule Win32_Ransomware_Sarbloh : tc_detection malicious
{
    meta:
        id = "3nbGRVcgbEpaH7rq5VgQtt"
        fingerprint = "v1_sha256_7259aa9d1fe657db220ee50f1610e6439ff61673d92f46ebc3b8cadd990f002c"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Sarbloh ransomware."
        category = "MALWARE"
        malware = "SARBLOH"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Sarbloh"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            8B 45 ?? C6 00 ?? 8B 45 ?? 40 89 45 ?? 39 75 ?? 72 ?? 6A ?? 8D 45 ?? C7 45 ?? ?? ??
            ?? ?? 50 6A ?? 6A ?? 6A ?? 6A ?? 52 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 75
            ?? 81 FE ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? 56 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ??
            ?? 8B D8 89 5D ?? 85 DB 0F 84 ?? ?? ?? ?? C1 E6 ?? 56 6A ?? 89 75 ?? FF 15 ?? ?? ??
            ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 7D ?? 8D 85 ?? ?? ?? ??
            6A ?? 6A ?? 50 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 8B
            8D ?? ?? ?? ?? 8B C1 8B 55 ?? 0B C2 89 4D ?? 89 55 ?? 0F 84 ?? ?? ?? ?? 0F 57 C0 66
            0F 13 45 ?? 85 D2 0F 8C ?? ?? ?? ?? 7F ?? 85 C9 0F 84 ?? ?? ?? ?? 8B 45 ?? 89 45 ??
            8B 45 ?? 89 45 ?? EB ?? 8B 75 ?? 8B 7D ?? 6A ?? 6A ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ??
            50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 8B 45 ?? 8B 4D ?? 89 4D ?? 89 45 ??
            85 C0 0F 8C ?? ?? ?? ?? 7F ?? 85 C9 0F 82 ?? ?? ?? ?? 6A ?? 6A ?? 8D 45 ?? 50 8D 85
            ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 6A ?? 6A ?? 56 8B 75 ??
            8D 45 ?? 56 50 6A ?? 6A ?? 6A ?? 57 FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 ?? 85 C0 0F
            85 ?? ?? ?? ?? 8B 75 ?? EB ?? 33 F6 8B 45 ?? 8B 4D ?? 89 75 ?? 89 4D ?? 89 45 ?? 85
            C0 0F 8C ?? ?? ?? ?? 7F ?? 85 C9 0F 82 ?? ?? ?? ?? 6A ?? 6A ?? 8D 45 ?? 50 8D 85 ??
            ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 33 FF 85 C0 0F 88 ?? ?? ?? ?? 85 F6 0F 84
        }

        $encrypt_files_p2 = {
            8B 75 ?? 8D 45 ?? 56 50 53 52 6A ?? 52 FF 75 ?? C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ??
            ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 6A ?? 56 53 8D 45 ?? 50 6A ?? 6A ?? 6A ?? FF 75 ??
            FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 8B 4D ??
            81 C7 ?? ?? ?? ?? 3B 7D ?? 72 ?? 8B 75 ?? 03 75 ?? 8B 45 ?? 83 D0 ?? 89 75 ?? 89 45
            ?? 3B 45 ?? 0F 8C ?? ?? ?? ?? 7F ?? 3B B5 ?? ?? ?? ?? 8B 75 ?? 0F 82 ?? ?? ?? ?? 8D
            45 ?? 50 6A ?? 6A ?? 6A ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? F7 D8 6A ?? 1B DB 8D 45
            ?? 23 5D ?? 50 6A ?? 6A ?? 6A ?? 6A ?? FF 75 ?? 89 5D ?? 89 5D ?? FF 15 ?? ?? ?? ??
            F7 D8 1B F6 23 75 ?? 56 6A ?? 89 75 ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F8
            85 FF 0F 84 ?? ?? ?? ?? 8D 45 ?? 89 5D ?? 50 57 6A ?? 6A ?? 6A ?? FF 75 ?? FF 15 ??
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 56 8D 45 ?? 89 5D ?? 50 57 6A ?? 6A ?? 6A ?? FF 75
            ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 6A ?? 56 57 8D 45 ?? 50 6A ?? 6A
            ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 ?? 85 C0 78 ?? 39 75 ?? 75 ??
            8B 85 ?? ?? ?? ?? 6A ?? 6A ?? 89 85 ?? ?? ?? ?? 8B 45 ?? 6A ?? 89 85 ?? ?? ?? ?? 8D
            85 ?? ?? ?? ?? 50 8D 45 ?? 89 9D ?? ?? ?? ?? 50 6A ?? 6A ?? 6A ?? FF 75 ?? 89 B5 ??
            ?? ?? ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 ?? 85 C0 78 ?? 33 C0 B9 ?? ?? ?? ?? 83
            7D ?? ?? 0F 44 C1 89 45 ?? 89 7D ?? 83 7D ?? ?? 74 ?? 8B 4D ?? 03 4D ?? 39 4D ?? 73
            ?? 90 8B 45 ?? C6 00 ?? 8B 45 ?? 40 89 45 ?? 39 4D ?? 72 ?? 57 6A ?? FF 15 ?? ?? ??
            ?? 50 FF 15 ?? ?? ?? ?? 8B 5D ?? 8B 7D ?? 8B 75 ?? EB
        }

        $find_files_p1 = {
            55 8B EC 83 EC ?? 53 56 8B 75 ?? 57 8B F9 83 3E ?? 0F 84 ?? ?? ?? ?? 6A ?? 6A ?? 8D
            45 ?? 50 52 FF 15 ?? ?? ?? ?? 6A ?? 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 89 45 ?? 8D
            45 ?? 50 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 57 C7 45 ?? ?? ?? ?? ?? C7
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 0F 89 4D ?? 85 C0 78 ??
            83 F9 ?? 74 ?? FF 75 ?? BB ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 50
            FF 15 ?? ?? ?? ?? 8B 55 ?? EB ?? FF 75 ?? C7 06 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ??
            50 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 8B 17 33 DB 89 55 ?? C7 45
            ?? ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 8B 4D ?? 81 C1 ?? ?? ?? ?? 39 4D ?? 73
        }

        $find_files_p2 = {
            8B 45 ?? C6 00 ?? 8B 45 ?? 40 89 45 ?? 39 4D ?? 72 ?? 53 6A ?? 6A ?? 6A ?? 68 ?? ??
            ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 6A ?? 6A ?? 52 FF 15 ?? ?? ?? ?? 8B F8 33 DB
            89 5D ?? 81 FF ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 55 ?? 85 FF 78 ?? 8B 4D ?? 8B 35 ??
            ?? ?? ?? 2B CB 0F 84 ?? ?? ?? ?? 83 E9 ?? 0F 85 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B C1
            C1 E8 ?? F7 D0 A8 ?? 74 ?? F7 C1 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 FE ?? 74 ?? 83 FE
            ?? 0F 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 C0
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
