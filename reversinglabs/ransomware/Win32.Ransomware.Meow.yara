rule Win32_Ransomware_Meow : tc_detection malicious
{
    meta:
        id = "1UjQqjjM6zbzFMdh1MthFE"
        fingerprint = "v1_sha256_b00753d2b150a815279297ddf40d70051d25de1c32bb90f5b706ea7fd36bb871"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Meow ransomware."
        category = "MALWARE"
        malware = "MEOW"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Meow"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            72 ?? 8D 45 ?? BA ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ??
            83 C4 ?? 68 ?? ?? ?? ?? 57 FF D0 85 C0 75 ?? 33 F6 6A ?? 68 ?? ?? ?? ?? BA ?? ?? ??
            ?? E8 ?? ?? ?? ?? 83 C4 ?? FF B4 B5 ?? ?? ?? ?? 57 FF D0 85 C0 75 ?? 46 83 FE ?? 7C
            ?? 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 5F 5E 33 C0 5B 8B E5 5D C3 CC 55 8B EC 83 EC
            ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 57 C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ??
            ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ??
            ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ??
            ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? 8A 45 ?? 80 7D ?? ??
            75
        }

        $encrypt_files_p2 = {
            8B 45 ?? 40 89 45 ?? 8B 45 ?? 99 F7 F9 85 D2 74 ?? E9 ?? ?? ?? ?? 8B 45 ?? 25 ?? ??
            ?? ?? 79 ?? 48 83 C8 ?? 83 C0 ?? 74 ?? 8B 4D ?? 8D 46 ?? 03 CF 0F AF C8 89 4D ?? 8B
            45 ?? 25 ?? ?? ?? ?? 79 ?? 48 83 C8 ?? 83 C0 ?? 75 ?? B9 ?? ?? ?? ?? 90 8B 45 ?? 99
            F7 F9 8B 45 ?? 85 D2 74 ?? 48 EB ?? 40 89 45 ?? 8B 45 ?? 25 ?? ?? ?? ?? 79 ?? 48 83
            C8 ?? 83 C0 ?? 74 ?? EB ?? 8B 45 ?? B9 ?? ?? ?? ?? 99 F7 F9 85 D2 74 ?? 8B 45 ?? 8D
            4E ?? 83 C0 ?? 99 F7 F9 B9 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 99 F7 F9 85 D2 75 ?? 8B 45
            ?? 99 F7 7D ?? 8B 45 ?? 85 D2 74 ?? 40 EB ?? 48 89 45 ?? 8B 45 ?? 99 F7 F9 85 D2 74
            ?? 6A ?? 68 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 FF
            D0 C7 45 ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 45 ?? 99 F7 F9 8B 45 ?? 85 D2 74 ?? 83 C0
            ?? 03 C3 89 45 ?? 8B 45 ?? 25 ?? ?? ?? ?? 79 ?? 48 83 C8 ?? 83 C0 ?? 0F 85
        }

        $drop_ransom_note = {
            66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 51 53 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85
            FF 74 ?? 8B CF E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 85 F6 74 ?? 6A
            ?? 68 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? FF D0 6A ??
            68 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A
            ?? 6A ?? 68 ?? ?? ?? ?? 56 FF D0 8B F0 BA ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 89 35 ??
            ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? 6A ?? 56 FF D0 B9 ?? ?? ?? ?? 8D BD ??
            ?? ?? ?? BE ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? F3 A5 68 ?? ?? ?? ?? 6A ?? 50 66 A5 A4 E8
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ??
            ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? 33 CD B8 ??
            ?? ?? ?? 5F 5B 5E E8 ?? ?? ?? ?? 8B E5 5D C3
        }

        $find_files = {
            53 53 53 51 F7 D0 23 85 ?? ?? ?? ?? 53 50 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 75 ?? FF
            B5 ?? ?? ?? ?? 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 E9 ?? ?? ?? ?? 8B 85 ?? ?? ??
            ?? 8B 48 ?? 2B 08 C1 F9 ?? 89 8D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89
            9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 ?? ?? ?? ??
            50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83
            C4 ?? F7 D8 1B C0 F7 D0 23 85 ?? ?? ?? ?? 80 38 ?? 75 ?? 8A 48 ?? 84 C9 74 ?? 80 F9
            ?? 75 ?? 38 58 ?? 74 ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 83
            C4 ?? 89 85 ?? ?? ?? ?? 85 C0 75 ?? 38 9D ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 ??
            ?? ?? ?? 59 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 85
            ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 10 8B 40 ?? 2B C2 C1 F8 ?? 3B C8 74 ?? 68 ?? ?? ??
            ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 38 9D ?? ?? ?? ?? 74 ??
            FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 59 8B D8 56 FF 15
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
            $drop_ransom_note
        )
}
