rule Win32_Ransomware_Networm : tc_detection malicious
{
    meta:
        id = "1v5MhU3bsMD9KPtXsVjFJI"
        fingerprint = "v1_sha256_ff9bcb9868522f9d4abf2ab9f94d5b7c9b009e5c6d0cf832c7d052f18e048b31"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Networm ransomware."
        category = "MALWARE"
        malware = "NETWORM"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Networm"
        tc_detection_factor = 5

    strings:

        $find_files = {
            68 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F1 89 B5 ?? ?? ?? ?? 8B 7D ?? 33 DB
            6A ?? 59 33 C0 89 5D ?? 89 4D ?? 66 89 45 ?? 89 5D ?? 89 5D ?? 89 4D ?? 66 89 45 ??
            68 ?? ?? ?? ?? 8B D7 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 4D ?? 3B C8
            74 ?? 88 9D ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ??
            ?? ?? ?? 83 7D ?? ?? 8D 8D ?? ?? ?? ?? 8D 45 ?? 0F 43 45 ?? 51 50 FF 15 ?? ?? ?? ??
            8B D8 83 FB ?? 0F 84 ?? ?? ?? ?? 66 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 6A ?? 8D
            4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B D7 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 8D
            ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ??
            C6 85 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 4D ?? 50 E8 ?? ?? ?? ??
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? F6 85
            ?? ?? ?? ?? ?? 8D 45 ?? 74 ?? 6A ?? 50 8B CE E8 ?? ?? ?? ?? 8B F0 85 F6 0F 85 ?? ??
            ?? ?? 8B B5 ?? ?? ?? ?? EB ?? 83 7D ?? ?? 68 ?? ?? ?? ?? 0F 43 45 ?? 50 FF 15 ?? ??
            ?? ?? 85 C0 74 ?? 83 7D ?? ?? 8D 45 ?? 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ??
            8D 85 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 53 FF 15 ?? ??
            ?? ?? 8B 1D ?? ?? ?? ?? FF D3 8B F0 83 FE ?? 75 ?? 83 7F ?? ?? 8B C7 72 ?? 8B 07 68
            ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 83 7F ?? ?? 72 ?? 8B 3F 57 FF 15 ?? ??
            ?? ?? 85 C0 75 ?? FF D3 8B F0 EB ?? FF 15 ?? ?? ?? ?? EB ?? 33 F6 8D 4D ?? E8 ?? ??
            ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? C2
        }

        $remote_connection_p1 = {
            55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 8B 5D ?? 56 57 6A ?? 8B FA 8B F1
            FF 15 ?? ?? ?? ?? 33 C0 50 50 89 45 ?? 89 45 ?? 8D 45 ?? 50 8D 45 ?? 50 6A ?? 57 56
            FF 15 ?? ?? ?? ?? 8B D3 8B C8 E8 ?? ?? ?? ?? 83 3B ?? 8B F0 75 ?? 68 ?? ?? ?? ?? EB
            ?? 81 3B ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ?? EB ?? 81 3B ?? ?? ??
            ?? 74 ?? 81 3B ?? ?? ?? ?? 74 ?? 85 F6 74 ?? 83 C8 ?? EB ?? 83 65 ?? ?? 8D 75 ?? 8B
            45 ?? 8B FB C6 45 ?? ?? C7 45 ?? ?? ?? ?? ?? A5 A5 A5 8B 4D ?? 5F 5E 33 CD 5B E8 ??
            ?? ?? ?? C9 C3
        }

        $remote_connection_p2 = {
            55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 8B 5D ?? 56 57 6A ?? 8B FA 8B F1
            FF 15 ?? ?? ?? ?? 33 C0 50 50 50 89 45 ?? 8D 45 ?? 50 FF 75 ?? 57 56 FF 15 ?? ?? ??
            ?? 8B D3 8B C8 E8 ?? ?? ?? ?? 83 3B ?? 8B F0 75 ?? 68 ?? ?? ?? ?? EB ?? 81 3B ?? ??
            ?? ?? 75 ?? 68 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ?? 85 F6 74 ?? 83 C8 ?? EB ?? 83 65 ??
            ?? 8D 75 ?? 8B 45 ?? 8B FB C6 45 ?? ?? C7 45 ?? ?? ?? ?? ?? A5 A5 A5 8B 4D ?? 5F 5E
            33 CD 5B E8 ?? ?? ?? ?? C9 C3
        }

        $encrypt_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? 53 56 57 A1 ?? ?? ?? ??
            33 C5 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B F1 8B 45 ?? 83 F8 ?? C7 45 ?? ?? ?? ?? ?? 0F
            94 C7 83 F8 ?? 0F 94 C3 83 F8 ?? 75 ?? B8 ?? ?? ?? ?? EB ?? 0F B6 C3 83 F0 ?? 8D 04
            45 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 50 6A ?? FF 76 ?? FF 15 ?? ?? ?? ?? 8B C8 89 4E ??
            85 C9 0F 84 ?? ?? ?? ?? 84 FF 74 ?? BF ?? ?? ?? ?? EB ?? 0F B6 C3 8D 3C 45 ?? ?? ??
            ?? 8B 56 ?? 8B 46 ?? 85 D2 7C ?? 0F 8F ?? ?? ?? ?? 85 C0 72 ?? 85 D2 7C ?? 0F 8F ??
            ?? ?? ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 83 F8 ?? 74 ?? 89 55 ?? EB ?? 0F 57 C0 66 0F 13
            45 ?? 8B 45 ?? FF 75 ?? 50 FF 75 ?? FF 75 ?? 57 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8D
            4D ?? 89 46 ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ??
            59 5F 5E 5B 8B E5 5D C2
        }

        $encrypt_files_p2 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? 56 A1 ?? ?? ?? ?? 33 C5
            50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B F1 83 7E ?? ?? C7 45 ?? ?? ?? ?? ?? 0F 85 ?? ?? ??
            ?? 8B 4D ?? 85 C9 74 ?? 83 7D ?? ?? 0F 85 ?? ?? ?? ?? EB ?? 8B 45 ?? 85 C0 74 ?? 0F
            8E ?? ?? ?? ?? 83 F8 ?? 7E ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? EB ?? F6 C1 ?? C7 45 ?? ??
            ?? ?? ?? B8 ?? ?? ?? ?? 0F 95 C0 40 89 45 ?? 83 7D ?? ?? 7F ?? 0F 8C ?? ?? ?? ?? 83
            7D ?? ?? 0F 82 ?? ?? ?? ?? 83 7D ?? ?? 7F ?? 0F 8C ?? ?? ?? ?? 83 7D ?? ?? 0F 82 ??
            ?? ?? ?? 83 EC ?? 8D 45 ?? 8B CC 50 E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 8D 45 ?? 8B
            CE 50 E8 ?? ?? ?? ?? 8D 45 ?? 8B CE 50 E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D
            ?? E8 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5E 8B E5 5D C2 ?? ?? 8D 45 ?? 6A
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 C6 45 ??
            ?? E8 ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 50 68 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 50 C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83
            C4 ?? 8D 4D ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 45
            ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 C6
            45 ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 50 68 ??
            ?? ?? ?? E8 ?? ?? ?? ?? 50 C6 45 ?? ?? E8
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            all of ($remote_connection_p*)
        )
}
