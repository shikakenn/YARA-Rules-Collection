rule ByteCode_MSIL_Ransomware_Moisha : tc_detection malicious
{
    meta:
        id = "5wQPtkDdgvI0uNISUqURFu"
        fingerprint = "v1_sha256_89cefbbb8ec722216721bb43eb14cc33fcd4671585051359a06b62236cbf3a6c"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Moisha ransomware."
        category = "MALWARE"
        malware = "MOISHA"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Moisha"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            73 ?? ?? ?? ?? 0A 02 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 2B ?? 07 6F ?? ?? ?? ?? 0C 08 28
            ?? ?? ?? ?? 2D ?? 06 08 6F ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 2D ?? DE ?? 07 2C ?? 07 6F ??
            ?? ?? ?? DC DE ?? 26 DE ?? 06 2A
        }

        $find_files_p2 = {
            02 28 ?? ?? ?? ?? 39 ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 0A 06 6F ?? ?? ?? ?? 6F ?? ?? ?? ??
            0B 2B ?? 07 6F ?? ?? ?? ?? 0C 08 6F ?? ?? ?? ?? 0D 03 09 6F ?? ?? ?? ?? 04 2C ?? 04 09
            6F ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 2D ?? DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? DC 06 6F ?? ??
            ?? ?? 6F ?? ?? ?? ?? 13 ?? 2B ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 03 04
            28 ?? ?? ?? ?? DE ?? 26 DE ?? 11 ?? 6F ?? ?? ?? ?? 2D ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ??
            ?? ?? ?? DC 02 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 03 11 ?? 6F ?? ?? ?? ?? 04 2C ?? 04
            11 ?? 6F ?? ?? ?? ?? 2A
        }

        $find_files_p3 = {
            73 ?? ?? ?? ?? 0A 06 03 7D ?? ?? ?? ?? 06 04 7D ?? ?? ?? ?? 06 05 7D ?? ?? ?? ?? 02 28
            ?? ?? ?? ?? 39 ?? ?? ?? ?? 06 02 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 06 7B ??
            ?? ?? ?? 2C ?? 06 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 16 31 ?? 06 7B ?? ?? ?? ?? 2C ?? 06 FE
            06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0B 07 17 6F ?? ?? ?? ?? 07 17 6F ?? ?? ??
            ?? 7E ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 07 6F ?? ?? ?? ?? DE ?? 26 DE ?? 02 28 ?? ?? ?? ??
            28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C 2B ?? 12 ?? 28 ?? ?? ?? ?? 0D 09 6F ?? ?? ?? ?? 06 7B
            ?? ?? ?? ?? 06 7B ?? ?? ?? ?? 06 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? 26 DE ?? 12 ?? 28
            ?? ?? ?? ?? 2D ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 2A
        }

        $import_priv_key = {
            02 73 ?? ?? ?? ?? 13 ?? 11 ?? 73 ?? ?? ?? ?? 13 ?? 16 13 ?? 16 13 ?? 16 13 ?? 11 ?? 6F
            ?? ?? ?? ?? 13 ?? 11 ?? 20 ?? ?? ?? ?? 33 ?? 11 ?? 6F ?? ?? ?? ?? 26 2B ?? 11 ?? 20 ??
            ?? ?? ?? 33 ?? 11 ?? 6F ?? ?? ?? ?? 26 2B ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 11 ?? 6F
            ?? ?? ?? ?? 13 ?? 11 ?? 20 ?? ?? ?? ?? 2E ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 11 ?? 6F
            ?? ?? ?? ?? 13 ?? 11 ?? 2C ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 11 ?? 28 ?? ?? ?? ?? 13
            ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 0A 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ??
            0B 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 0C 11 ?? 28 ?? ?? ?? ?? 13 ??
            11 ?? 11 ?? 6F ?? ?? ?? ?? 0D 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 13
            ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 13
            ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ??
            ?? 13 ?? 12 ?? FE 15 ?? ?? ?? ?? 12 ?? 06 7D ?? ?? ?? ?? 12 ?? 07 7D ?? ?? ?? ?? 12 ??
            08 7D ?? ?? ?? ?? 12 ?? 09 7D ?? ?? ?? ?? 12 ?? 11 ?? 7D ?? ?? ?? ?? 12 ?? 11 ?? 7D ??
            ?? ?? ?? 12 ?? 11 ?? 7D ?? ?? ?? ?? 12 ?? 11 ?? 7D ?? ?? ?? ?? 11 ?? 13 ?? DE ?? 11 ??
            6F ?? ?? ?? ?? DC 11 ?? 2A
        }

        $encrypt_files = {
            20 ?? ?? ?? ?? 8D ?? ?? ?? ?? 0A 14 0B 14 0C 16 0D 20 ?? ?? ?? ?? 13 ?? 03 19 17 1D 28
            ?? ?? ?? ?? 0B 03 19 18 1D 28 ?? ?? ?? ?? 0C 02 7B ?? ?? ?? ?? 08 17 6F ?? ?? ?? ?? 13
            ?? 07 06 16 06 8E 69 6F ?? ?? ?? ?? 13 ?? 11 ?? 16 31 ?? 11 ?? 06 16 11 ?? 6F ?? ?? ??
            ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 04 11 ?? 6F ?? ?? ?? ?? 04 6F ?? ?? ?? ??
            13 ?? 11 ?? 8E 69 13 ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 08 08 6F ?? ?? ?? ?? 16 6F ?? ?? ??
            ?? 26 08 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 08 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 08
            6F ?? ?? ?? ?? 17 0D DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC DE ?? 13 ?? DE ?? 07 2C
            ?? 07 6F ?? ?? ?? ?? 08 2C ?? 08 6F ?? ?? ?? ?? 09 26 DC 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            $import_priv_key
        ) and
        (
            $encrypt_files
        )
}
