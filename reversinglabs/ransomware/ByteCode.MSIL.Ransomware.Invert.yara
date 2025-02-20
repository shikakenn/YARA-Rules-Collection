rule ByteCode_MSIL_Ransomware_Invert : tc_detection malicious
{
    meta:
        id = "3JIA73s6avPamXY29aZWyV"
        fingerprint = "v1_sha256_1608b8bbfc03b18a79752e60f211da7d7703862bc06b2ddf094074ae5efd0d14"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Invert ransomware."
        category = "MALWARE"
        malware = "INVERT"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Invert"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            73 ?? ?? ?? ?? 0A 06 04 7D ?? ?? ?? ?? 00 00 02 28 ?? ?? ?? ?? 06 7B ?? ?? ?? ?? 25 2D
            ?? 26 06 06 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 0C 7D ?? ?? ?? ?? 08 7E ?? ?? ?? ?? 25
            2D ?? 26 7E ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 7E ?? ?? ?? ?? 25 2D ?? 26 7E ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ??
            ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 25 2D ?? 26 7E ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73
            ?? ?? ?? ?? 25 80 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 25 2D ?? 26 7E ?? ?? ?? ??
            FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 25 2D
            ?? 26 7E ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ?? ?? ?? 28 ?? ?? ?? ??
            7E ?? ?? ?? ?? 25 2D ?? 26 7E ?? ?? ?? ?? FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 2B ?? 07 6F ?? ?? ?? ?? 0D 00 00 09 03 28 ?? ??
            ?? ?? 13 ?? 11 ?? 2C ?? 00 7E ?? ?? ?? ?? 09 6F ?? ?? ?? ?? 26 00 00 DE ?? 26 00 00 DE
            ?? 00 07 6F ?? ?? ?? ?? 2D ?? DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? 00 DC 2A
        }

        $find_files = {
            00 73 ?? ?? ?? ?? 0A 00 28 ?? ?? ?? ?? 18 8D ?? ?? ?? ?? 25 16 28 ?? ?? ?? ?? A2 25 17
            72 ?? ?? ?? ?? A2 17 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 2B ?? 12 ?? 28 ??
            ?? ?? ?? 0C 00 06 08 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 26 00 12 ?? 28 ?? ?? ?? ?? 2D ?? DE
            ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 DC 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 26 06
            0D 2B ?? 09 2A
        }

        $get_file_list = {
            00 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 06 2C
            ?? 00 02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 00 00 38 ?? ??
            ?? ?? 00 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0B
            00 00 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C 2B ?? 12 ?? 28 ?? ?? ?? ?? 0D 00 07 09 6F ?? ??
            ?? ?? 00 00 12 ?? 28 ?? ?? ?? ?? 2D ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? 00
            DC 00 DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? 00 DC 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ??
            ?? 28 ?? ?? ?? ?? 18 28 ?? ?? ?? ?? 00 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28
            ?? ?? ?? ?? 18 28 ?? ?? ?? ?? 00 02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 00 00 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $get_file_list
        ) and
        (
            $find_files
        ) and
        (
            $encrypt_files
        )
}
