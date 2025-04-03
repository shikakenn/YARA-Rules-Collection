rule ByteCode_MSIL_Ransomware_EAF : tc_detection malicious
{
    meta:
        id = "12p099LNYhrLDTJyIecStd"
        fingerprint = "v1_sha256_3d10c852f95e8aa9bcd3543b96650b98ac57bcd2aa2b374e0badb63b5a4c0396"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects EAF ransomware."
        category = "MALWARE"
        malware = "EAF"
        tc_detection_type = "Ransomware"
        tc_detection_name = "EAF"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            00 03 28 ?? ?? ?? ?? 0A 06 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 07 39 ?? ?? ?? ?? 00 7E ??
            ?? ?? ?? 0C 03 28 ?? ?? ?? ?? 0D 03 28 ?? ?? ?? ?? 13 ?? 1E 8D ?? ?? ?? ?? 25 16 11 ??
            A2 25 17 72 ?? ?? ?? ?? A2 25 18 7E ?? ?? ?? ?? A2 25 19 72 ?? ?? ?? ?? A2 25 1A 28 ??
            ?? ?? ?? A2 25 1B 72 ?? ?? ?? ?? A2 25 1C 09 A2 25 1D 72 ?? ?? ?? ?? A2 28 ?? ?? ?? ??
            13 ?? 02 03 11 ?? 08 28 ?? ?? ?? ?? 13 ?? 11 ?? 2D ?? 06 72 ?? ?? ?? ?? 28 ?? ?? ?? ??
            2B ?? 16 13 ?? 11 ?? 2C ?? 00 00 03 11 ?? 28 ?? ?? ?? ?? 00 00 DE ?? 26 00 00 DE ?? 00
            00 00 DE ?? 26 00 00 DE ?? 2A
        }

        $encrypt_files_p2 = {
            00 03 19 73 ?? ?? ?? ?? 0A 00 04 18 73 ?? ?? ?? ?? 0B 00 06 16 6A 6F ?? ?? ?? ?? 00 28
            ?? ?? ?? ?? 0C 00 1F ?? 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0D 05 09 73 ??
            ?? ?? ?? 13 ?? 00 08 17 6F ?? ?? ?? ?? 00 08 18 6F ?? ?? ?? ?? 00 08 11 ?? 1F ?? 6F ??
            ?? ?? ?? 6F ?? ?? ?? ?? 00 08 11 ?? 1F ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 07 08 6F ??
            ?? ?? ?? 17 73 ?? ?? ?? ?? 13 ?? 00 20 ?? ?? ?? ?? 13 ?? 11 ?? 8D ?? ?? ?? ?? 13 ?? 16
            13 ?? 00 06 11 ?? 16 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 20 ?? ?? ?? ?? FE 02 16 FE 01 13
            ?? 11 ?? 2C ?? 00 11 ?? 11 ?? 16 11 ?? 6F ?? ?? ?? ?? 00 00 2B ?? 11 ?? 20 ?? ?? ?? ??
            32 ?? 11 ?? 20 ?? ?? ?? ?? FE 02 16 FE 01 2B ?? 16 13 ?? 11 ?? 2C ?? 00 11 ?? 11 ?? 16
            11 ?? 6F ?? ?? ?? ?? 00 00 2B ?? 11 ?? 20 ?? ?? ?? ?? 32 ?? 11 ?? 20 ?? ?? ?? ?? FE 02
            16 FE 01 2B ?? 16 13 ?? 11 ?? 2C ?? 00 11 ?? 11 ?? 16 11 ?? 6F ?? ?? ?? ?? 00 00 2B ??
            00 07 11 ?? 16 11 ?? 6F ?? ?? ?? ?? 00 00 11 ?? 11 ?? 58 13 ?? 00 11 ?? 16 FE 03 13 ??
            11 ?? 3A ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 00 00 DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ??
            00 DC 00 DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? 00 DC 00 DE ?? 08 2C ?? 08 6F ?? ?? ??
            ?? 00 DC 07 6F ?? ?? ?? ?? 00 00 DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? 00 DC 06 6F ?? ?? ??
            ?? 00 00 DE ?? 06 2C ?? 06 6F ?? ?? ?? ?? 00 DC 03 28 ?? ?? ?? ?? 00 17 13 ?? DE ?? 26
            00 16 13 ?? DE ?? 11 ?? 2A
        }

        $find_files_p1 = {
            72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 16 0C 38 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0D 00 09 06 08 9A
            28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 06 08 9A 28 ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 09 FE 06 ??
            ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 09 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ??
            ?? ?? 2C ?? 11 ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 11 ?? 7E ?? ?? ?? ?? 28 ?? ?? ??
            ?? 2B ?? 16 13 ?? 11 ?? 2C ?? 00 7E ?? ?? ?? ?? 06 08 9A 6F ?? ?? ?? ?? 00 00 00 08 17
            58 0C 08 06 8E 69 FE 04 13 ?? 11 ?? 3A ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 16
            13 ?? 2B ?? 00 07 11 ?? 9A 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 07 11 ?? 9A 72 ?? ?? ??
            ?? 28 ?? ?? ?? ?? 2C ?? 07 11 ?? 9A 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 07 11 ?? 9A 72
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 2B ?? 16 13 ?? 11 ?? 2C ?? 00 07 11 ?? 9A 28 ?? ?? ?? ?? 00
            00 00 11 ?? 17 58 13 ?? 11 ?? 07 8E 69 FE 04 13 ?? 11 ?? 2D ?? 00 DE ?? 26 00 00 DE ??
            2A
        }

        $find_files_p2 = {
            00 28 ?? ?? ?? ?? 0A 16 0B 2B ?? 73 ?? ?? ?? ?? 0C 08 06 07 9A 7D ?? ?? ?? ?? 00 08 7B
            ?? ?? ?? ?? 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 08 7B ?? ?? ?? ?? 6F ??
            ?? ?? ?? 2B ?? 16 0D 09 2C ?? 00 08 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 73 ?? ?? ?? ?? 28
            ?? ?? ?? ?? 00 00 00 07 17 58 0B 07 06 8E 69 32 ?? 00 DE ?? 26 00 00 DE ?? 2A
        }

        $destroy_exe_file = {
            00 1F ?? 28 ?? ?? ?? ?? 0A 72 ?? ?? ?? ?? 0B 7E ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 0C 7E ??
            ?? ?? ?? 07 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C 08 72 ?? ?? ?? ?? 1B 8D ??
            ?? ?? ?? 25 16 72 ?? ?? ?? ?? A2 25 17 06 A2 25 18 72 ?? ?? ?? ?? A2 25 19 28 ?? ?? ??
            ?? A2 25 1A 72 ?? ?? ?? ?? A2 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 08 6F ?? ?? ?? ?? 00 00
            DE ?? 26 00 00 DE ?? 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            $destroy_exe_file
        )
}
