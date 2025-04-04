rule ByteCode_MSIL_Ransomware_Khonsari : tc_detection malicious
{
    meta:
        id = "7ka2qRbmYfcfCrcYhrj5Os"
        fingerprint = "v1_sha256_f1003b7863215bcd8e5cdce8ce40551105fb668ea2b8ac765909f9fa5373e6ca"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Khonsari ransomware."
        category = "MALWARE"
        malware = "KHONSARI"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Khonsari"
        tc_detection_factor = 5

    strings:

        $find_files = {
            73 ?? ?? ?? ?? 0A 73 ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 72 ?? ?? ?? ??
            13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 28 ?? ?? ?? ?? 0B
            16 0C 2B ?? 07 08 9A 0D 09 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 72 ??
            ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 06 09
            6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 08 17 58 0C 08 07 8E 69 32 ?? 06 1B 28 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 06 1F ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 1F ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ??
            06 1F ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11
            ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 1F ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ??
            06 6F ?? ?? ?? ?? 13 ?? 38 ?? ?? ?? ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ??
            6F ?? ?? ?? ?? 13 ?? 2B ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 2D ?? 00 11
            ?? 7E ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 11 ?? 72 ??
            ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 28 ?? ?? ?? ?? DE ?? 26 DE ?? 11 ?? 6F ?? ?? ?? ?? 2D ?? DE ?? 11 ?? 2C ?? 11 ?? 6F
            ?? ?? ?? ?? DC DE ?? 26 DE ?? 12 ?? 28 ?? ?? ?? ?? 3A ?? ?? ?? ?? DE ?? 12 ?? FE 16 ??
            ?? ?? ?? 6F ?? ?? ?? ?? DC 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ??
            28 ?? ?? ?? ?? 26 2A
        }

        $get_key = {
            73 ?? ?? ?? ?? 0A 06 12 ?? FE 15 ?? ?? ?? ?? 12 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11
            ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D
            ?? ?? ?? ?? 12 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 72 ??
            ?? ?? ?? 13 ?? 11 ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 07 6F ??
            ?? ?? ?? 06 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 13 ?? 11
            ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 06 02 7B ?? ?? ?? ?? 17 6F ??
            ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C DE ?? 06 2C ?? 06 6F ?? ?? ?? ?? DC 08 2A
        }

        $encrypt_files = {
            28 ?? ?? ?? ?? 0A 06 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 13 ?? 11 ?? 6F ?? ?? ?? ?? 06 20
            ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 13 ?? 11 ?? 6F ?? ??
            ?? ?? 06 19 6F ?? ?? ?? ?? 06 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 02 7B ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 06 06 6F ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 02 03 07 28 ?? ??
            ?? ?? 0C DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? DC 06 2C ?? 06 6F ?? ?? ?? ?? DC 08 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            $get_key
        ) and
        (
            $encrypt_files
        )
}
