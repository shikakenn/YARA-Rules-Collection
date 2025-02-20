rule ByteCode_MSIL_Ransomware_WildFire : tc_detection malicious
{
    meta:
        id = "1z97JDmaZxJ2vgmHLOn86E"
        fingerprint = "v1_sha256_d3be2eac7967853aae6e1317d9c22d95a3dc4b3e5bf8acbe97a7bbeabc9eab38"
        version = "1.0"
        modified = "2025-02-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects WildFire ransomware."
        category = "MALWARE"
        malware = "WILDFIRE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "WildFire"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            00 02 19 17 73 ?? ?? ?? ?? 0A 1B 8D ?? ?? ?? ?? 25 16 02 16 02 [5-10] 6F ?? ?? ?? ??
            6F ?? ?? ?? ?? A2 25 17 [5-10] A2 25 18 7E ?? ?? ?? ?? A2 25 19 [5-10] A2 25 1A 02 02
            [5-10] 6F ?? ?? ?? ?? 17 D6 6F ?? ?? ?? ?? A2 28 ?? ?? ?? ?? 0B 07 [5-10] 28 ?? ?? ??
            ?? 1A 18 73 ?? ?? ?? ?? 0C 08 21 00 00 00 00 00 00 00 00 6F ?? ?? ?? ?? 20 ?? ?? ?? ??
            8D ?? ?? ?? ?? 0D 21 00 00 00 00 00 00 00 00 13 ?? 06 6F ?? ?? ?? ?? 13 ?? 73 ?? ?? ??
            ?? 13 ?? 08 11 ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? 17 73 ?? ?? ?? ?? 13 ??
            2B ?? 06 09 16 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 09 16 11 ?? 6F ?? ?? ?? ?? 11
            ?? 11 ?? 6A D6 13 ?? 11 ?? 11 ?? FE ?? 2D ?? 11 ?? 6F ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 08
            6F ?? ?? ?? ?? 7E ?? ?? ?? ?? 17 D6 80 ?? ?? ?? ?? 02 28 ?? ?? ?? ?? DE ?? 28 ?? ?? ??
            ?? 28 ?? ?? ?? ?? DE ?? 2A            
        }

        $enum_drives = {
            00 00 28 ?? ?? ?? ?? 1F ?? 0A 18 0C 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 19 0C 28 ?? ?? ?? ?? 0D 1A
            0C 09 13 ?? 16 13 ?? 11 ?? 11 ?? 8E 69 FE ?? 2C ?? 11 ?? 11 ?? 9A 13 ?? 1B 0C 11 ??
            6F ?? ?? ?? ?? 2C ?? 1C 0C 11 ?? 6F ?? ?? ?? ?? 19 FE ?? 16 FE ?? 65 18 60 1A 60 11
            ?? 6F ?? ?? ?? ?? 21 ?? ?? ?? ?? ?? ?? ?? ?? FE ?? 16 FE ?? 65 5F 16 FE ?? 2C ?? 1D
            0C 11 ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 17 28 ?? ?? ?? ?? 1E 0C 11 ?? 6F ?? ?? ?? ??
            6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 1F ?? 0C 11 ?? 17 D6 13 ?? 2B
        }

        $file_search = {
            A2 25 20 ?? ?? ?? ?? [5-10] A2 25 20 ?? ?? ?? ?? [5-10] A2 25 20 ?? ?? ?? ?? [5-10] 
            A2 25 20 ?? ?? ?? ?? [5-10] A2 25 20 ?? ?? ?? ?? [5-10] A2 0D 19 0C 19 8D ?? ?? ?? ??
            25 16 [5-10] A2 25 17 [5-10] A2 25 18 [5-10] A2 13 04 1A 0C 02 28 ?? ?? ?? ?? 13 ?? 1B
            0C 11 ?? 8E 69 17 DA 13 ?? 16 13 ?? 11 ?? 11 ?? (30 | 3D) [1-4] 1C 0C 11 ?? 11 ?? 9A 28
            ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 1D 0C 09 11 ?? 6F ?? ?? ?? ?? 11 ?? 11 ?? 9A [5-10] 6F
            ?? ?? ?? ?? 16 FE ?? 5F 11 ?? 11 ?? 9A 1F ?? 28 ?? ?? ?? ?? [5-10] 28 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 16 FE ?? 5F 11 ?? [5-10] 16 28 ?? ?? ?? ?? 16 FE ?? 5F 2C ?? 1E 0C 11 ?? 11 ?? 
            9A 28 ?? ?? ?? ?? 1F ?? 0C 11 ?? 17 D6 13 ?? (38 | 2B) [1-4] 1F ?? 0C 02 28 ?? ?? ?? ??
            13 ?? 1F ?? 0C 11 ?? 8E 69 17 DA 13 ?? 16 13 ?? 11 ?? 11 ?? 30 ?? 1F ?? 0C 11 ?? 11 ??
            11 ?? 9A 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 16 FE ?? 2C ?? 1F ?? 0C 11 ?? 11 ?? 9A 28 ?? ??
            ?? ?? 1F ?? 0C 11 ?? 17 D6 13 ?? 2B ?? 1F ?? 0C 02 17 8D ?? ?? ?? ?? 25 16 1F ?? 9D 6F
            ?? ?? ?? ?? 8E 69 17 DA 18 FE ?? 16 FE ?? 2C ?? 1F ?? 0C 02 16 28 ?? ?? ?? ?? DD ?? ??
            ?? ?? 07 17 58 16 0B 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
            ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
            ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
            ?? ?? ?? ?? ?? ?? ?? ?? ?? DE
        }

        $remote_server_communication_1 = {
            00 7E ?? ?? ?? ?? 73 ?? ?? ?? ?? 16 7E ?? ?? ?? ?? 8E 69 6F ?? ?? ?? ?? 9A [5-10] 28 ??
            ?? ?? ?? 0B 02 [5-10] 16 28 ?? ?? ?? ?? 16 FE ?? 3A ?? ?? ?? ?? 02 [5-10] 16 28 ?? ?? ??
            ?? 16 FE ?? 39 ?? ?? ?? ?? 1D 8D ?? ?? ?? ?? 25 16 [5-10] A2 25 17 02 A2 25 18 [5-10] A2
            25 19 7E ?? ?? ?? ?? A2 25 1A [5-10] A2 25 1B 7E ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 25 1C [5-10]
            A2 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 13 ??
            [5-10] 11 ?? 28 ?? ?? ?? ?? 13 ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 07
            28 ?? ?? ?? ?? 74 ?? ?? ?? ?? 13 ?? 11 ?? [5-10] 6F ?? ?? ?? ?? 11 ?? [5-10] 6F ?? ?? ?? ??
            11 ?? 11 ?? 8E 69 6A 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 16 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ??
            ?? 13 ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ??
            74 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11
        }

    condition:
        uint16(0) == 0x5A4D and $enum_drives and $file_search and $encrypt_files and $remote_server_communication_1
}
