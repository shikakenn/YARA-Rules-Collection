rule ByteCode_MSIL_Ransomware_Namaste : tc_detection malicious
{
    meta:
        id = "5VjkpnD9Hiptt8GqGggHyq"
        fingerprint = "v1_sha256_5a952276f41b5524bcb82a9ceb076983d2faf2864b3bbd0a06d49bbd5edc1e0e"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Namaste ransomware."
        category = "MALWARE"
        malware = "NAMASTE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Namaste"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            03 28 ?? ?? ?? ?? 0A 16 0B 2B ?? 02 06 07 9A 28 ?? ?? ?? ?? 07 17 58 0B 07 06 8E 69 32
            ?? DE ?? 26 DE ?? 00 03 28 ?? ?? ?? ?? 0C 16 0D 2B ?? 08 09 9A 13 ?? 02 11 ?? 28 ?? ??
            ?? ?? 17 28 ?? ?? ?? ?? 09 17 58 0D 09 08 8E 69 32 ?? DE ?? 26 DE ?? 2A
        }

        $find_files_p2 = {
            02 7B ?? ?? ?? ?? 2D ?? 03 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2C ?? 17 2A 03 6F ?? ?? ?? ??
            0A 06 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 3A ?? ?? ?? ?? 06 72 ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 3A ?? ?? ?? ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? ?? ?? 06 72 ?? ??
            ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? ?? ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? ?? ?? 06
            72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? ?? ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ??
            ?? ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06
            72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 72 ?? ??
            ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 72 ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 2D ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ??
            ?? 2D ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2C ?? 16 2A 02 7B ?? ?? ?? ?? 2C ?? 03 72 ??
            ?? ?? ?? 6F ?? ?? ?? ?? 2C ?? 16 2A 02 7B ?? ?? ?? ?? 2D ?? 03 72 ?? ?? ?? ?? 6F ?? ??
            ?? ?? 2D ?? 16 2A 03 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 03 73 ?? ?? ?? ?? 28 ?? ?? ?? ??
            20 ?? ?? ?? ?? 6A 31 ?? 16 0C DE ?? DE ?? 26 DE ?? 02 28 ?? ?? ?? ?? 07 28 ?? ?? ?? ??
            2A 08 2A
        }

        $encrypt_files_p1 = {
            02 03 28 ?? ?? ?? ?? 2C ?? 02 7B ?? ?? ?? ?? 2C ?? 02 03 72 ?? ?? ?? ?? 28 ?? ?? ?? ??
            02 7B ?? ?? ?? ?? 03 6F ?? ?? ?? ?? 02 7C ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 2B ?? 02 03 72
            ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? 26 DE ?? 02 7B ?? ?? ?? ?? 2C ?? 03 72 ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 2C ?? 02 7C ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 2A
        }

        $encrypt_files_p2 = {
            1F ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 02 20 ?? ?? ??
            ?? 7D ?? ?? ?? ?? 02 17 7D ?? ?? ?? ?? 02 17 7D ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ??
            ?? 25 2D ?? 26 7E ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ?? ?? ?? 28 ??
            ?? ?? ?? 28 ?? ?? ?? ?? 02 1F ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 1B 28 ?? ?? ?? ?? 28
            ?? ?? ?? ?? 02 1F ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 1F ?? 28 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 02 1F ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 1F ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 1F
            ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0A 2B ?? 12 ?? 28 ?? ?? ?? ?? 0B 02 07
            28 ?? ?? ?? ?? 12 ?? 28 ?? ?? ?? ?? 2D ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ??
            DC 02 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2A
        }

        $encrypt_files_p3 = {
            28 ?? ?? ?? ?? 04 6F ?? ?? ?? ?? 26 73 ?? ?? ?? ?? 0A 06 20 ?? ?? ?? ?? 6F ?? ?? ?? ??
            06 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 18 6F ?? ?? ?? ?? 04 14 73 ?? ?? ?? ?? 0B 06 07 06
            6F ?? ?? ?? ?? 1E 5B 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 07 06 6F ?? ?? ?? ?? 1E 5B 6F ??
            ?? ?? ?? 6F ?? ?? ?? ?? 06 1A 6F ?? ?? ?? ?? 03 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 18 73 ??
            ?? ?? ?? 0C 08 06 6F ?? ?? ?? ?? 17 73 ?? ?? ?? ?? 0D 03 19 73 ?? ?? ?? ?? 13 ?? 20 ??
            ?? ?? ?? 8D ?? ?? ?? ?? 13 ?? 2B ?? 09 11 ?? 16 11 ?? 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11
            ?? 8E 69 6F ?? ?? ?? ?? 25 13 ?? 16 30 ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 09
            2C ?? 09 6F ?? ?? ?? ?? DC 08 2C ?? 08 6F ?? ?? ?? ?? DC 03 28 ?? ?? ?? ?? 2A
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
