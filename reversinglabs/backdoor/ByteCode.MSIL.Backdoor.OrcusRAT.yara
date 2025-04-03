rule ByteCode_MSIL_Backdoor_OrcusRAT : tc_detection malicious
{
    meta:
        id = "4MTEvREO1lecX7fRR3QYdV"
        fingerprint = "v1_sha256_17a85613e9e4c862ce81fee49065c250381dbf8a50cf07d496f5fd2c1b82d92e"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects OrcusRAT backdoor."
        category = "MALWARE"
        malware = "ORCUSRAT"
        tc_detection_type = "Backdoor"
        tc_detection_name = "OrcusRAT"
        tc_detection_factor = 5

    strings:

        $get_tcp_connections = {
            18 0B 16 0C 7E ?? ?? ?? ?? 12 ?? 17 07 1B 16 28 ?? ?? ?? ?? 0D 09 2C ?? 09 1F ?? 2E
            ?? 72 ?? ?? ?? ?? 09 8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 08 28 ?? ?? ??
            ?? 13 ?? 11 ?? 12 ?? 17 07 1B 16 28 ?? ?? ?? ?? 0D 09 2C ?? 72 ?? ?? ?? ?? 09 8C ??
            ?? ?? ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 7A 11 ?? D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ??
            ?? ?? ?? A5 ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 8C ?? ?? ??
            ?? 28 ?? ?? ?? ?? 6A 58 28 ?? ?? ?? ?? 13 ?? 11 ?? 7B ?? ?? ?? ?? 8D ?? ?? ?? ?? 0A
            16 13 ?? 2B ?? 11 ?? D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? A5 ?? ?? ?? ?? 13
            ?? 06 11 ?? 11 ?? A4 ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 11 ?? 8C ?? ?? ?? ?? 28 ?? ??
            ?? ?? 6A 58 28 ?? ?? ?? ?? 13 ?? 11 ?? 17 58 13 ?? 11 ?? 6A 11 ?? 7B ?? ?? ?? ?? 6E
            32 ?? DE ?? 11 ?? 28 ?? ?? ?? ?? DC 06 7E ?? ?? ?? ?? 25 2D ?? 26 7E ?? ?? ?? ?? (FE | 06)
            ?? ?? ?? ?? ?? 73 ?? ?? ?? ?? 25 80 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28
        }

        $get_operating_system_information_p1 = {
            73 ?? ?? ?? ?? 25 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 25 28 ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 0B 12 ?? (FE | 16) ?? ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 25 28 ??
            ?? ?? ?? 6F ?? ?? ?? ?? 25 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 25 28 ?? ??
            ?? ?? 6F ?? ?? ?? ?? 25 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 25 28 ?? ?? ?? ?? 6F ?? ?? ??
            ?? 0A 28 ?? ?? ?? ?? 0C 08 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2B ??
            06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2B ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2B ?? 06 72
            ?? ?? ?? ?? 6F ?? ?? ?? ?? 2B ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 73 ?? ?? ?? ?? 0D
            09 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 7D ?? ?? ?? ?? 06 09 (FE | 06) ??
            ?? ?? ?? ?? 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 72 ?? ??
            ?? ?? 6F ?? ?? ?? ?? 39 ?? ?? ?? ?? 09 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ??
            6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 20 ?? ?? ?? ?? 2F ?? 06 1C 8D ?? ?? ?? ??
            25 16 09 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? A2 25 17 72 ?? ?? ?? ?? A2 25
            18 09 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? A2 25 19 72 ?? ?? ?? ?? A2 25 1A
            11 ?? 8C ?? ?? ?? ?? A2 25 1B 72 ?? ?? ?? ?? A2 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 38 ??
            ?? ?? ?? 06 1C 8D ?? ?? ?? ?? 25 16 09 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F
        }

        $get_operating_system_information_p2 = {
            A2 25 17 72 ?? ?? ?? ?? A2 25 18 11 ?? 8C ?? ?? ?? ?? A2 25 19 72 ?? ?? ?? ?? A2 25
            1A 09 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? A2 25 1B 72 ?? ?? ?? ?? A2 28 ??
            ?? ?? ?? 6F ?? ?? ?? ?? 2B ?? 06 1A 8D ?? ?? ?? ?? 25 16 09 7B ?? ?? ?? ?? 72 ?? ??
            ?? ?? 6F ?? ?? ?? ?? A2 25 17 72 ?? ?? ?? ?? A2 25 18 09 7B ?? ?? ?? ?? 72 ?? ?? ??
            ?? 6F ?? ?? ?? ?? A2 25 19 72 ?? ?? ?? ?? A2 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 26
            06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 06 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 39 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 28
            ?? ?? ?? ?? 13 ?? 11 ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 33 ?? 06 72 ?? ?? ?? ?? 6F ?? ??
            ?? ?? 38 ?? ?? ?? ?? 11 ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 33 ?? 06 72 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 38 ?? ?? ?? ?? 11 ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 33 ?? 06 6F ?? ?? ?? ?? 72
            ?? ?? ?? ?? 6F ?? ?? ?? ?? 2C ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 38 ?? ?? ?? ?? 06
            6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 39 ?? ?? ?? ?? 06 72 ?? ?? ?? ?? 6F ??
            ?? ?? ?? 2B ?? 11 ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 33 ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ??
            ?? 2B ?? 11 ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 2E ?? 11 ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 33
            ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2B ?? 11 ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 2E ?? 11
            ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 2E ?? 06 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ??
            2C ?? 06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 06 72
            ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 09 7B ?? ?? ?? ?? 2C ?? 09 7B ?? ?? ?? ?? 6F ?? ??
            ?? ?? DC 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 73 ?? ?? ?? ?? 13 ?? 11
        }

        $take_screenshot = {
            28 ?? ?? ?? ?? 0B 12 ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 12 ?? 28 ?? ?? ?? ?? 73 ??
            ?? ?? ?? 0A 06 28 ?? ?? ?? ?? 0C 08 28 ?? ?? ?? ?? 0B 12 ?? 28 ?? ?? ?? ?? 28 ?? ??
            ?? ?? 0B 12 ?? 28 ?? ?? ?? ?? 16 16 06 6F ?? ?? ?? ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ??
            DE ?? 08 2C ?? 08 6F ?? ?? ?? ?? DC 06
        }

        $get_passwords = {
            1F ?? 8D ?? ?? ?? ?? 25 16 73 ?? ?? ?? ?? A2 25 17 73 ?? ?? ?? ?? A2 25 18 73 ?? ??
            ?? ?? A2 25 19 73 ?? ?? ?? ?? A2 25 1A 73 ?? ?? ?? ?? A2 25 1B 73 ?? ?? ?? ?? A2 25
            1C 73 ?? ?? ?? ?? A2 25 1D 73 ?? ?? ?? ?? A2 25 1E 73 ?? ?? ?? ?? A2 25 1F ?? 73 ??
            ?? ?? ?? A2 25 1F ?? 73 ?? ?? ?? ?? A2 25 1F ?? 73 ?? ?? ?? ?? A2 0A 73 ?? ?? ?? ??
            25 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 25 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 06 0C 16 0D 2B
            ?? 08 09 9A 13 ?? 07 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 26 DE
            ?? 09 17 58 0D 09 08 8E 69 32 ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ??
            2B ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 2C ?? 11 ?? 6F ??
            ?? ?? ?? 16 31 ?? 07 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? DE ?? 26 DE ?? 12 ?? 28 ??
            ?? ?? ?? 2D ?? DE ?? 12 ?? (FE | 16) ?? ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 02 39 ?? ?? ??
            ?? 06 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 2B ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 07 6F ??
            ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 26 DE ?? 11 ?? 6F ?? ?? ?? ?? 2D
            ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ??
            ?? ?? 13 ?? 2B ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 2C ??
            11 ?? 6F ?? ?? ?? ?? 16 31 ?? 07 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? DE ?? 26 DE ??
            12 ?? 28 ?? ?? ?? ?? 2D ?? DE ?? 12 ?? (FE | 16) ?? ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 07
        }

        $process_key_action = {
            03 28 ?? ?? ?? ?? 2C ?? 02 17 7D ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 02 7B ?? ?? ?? ?? 1A
            8D ?? ?? ?? ?? 25 16 03 8C ?? ?? ?? ?? A2 25 17 04 8C ?? ?? ?? ?? A2 25 18 05 8C ??
            ?? ?? ?? A2 25 19 07 A2 6F ?? ?? ?? ?? 26 2A 02 7B ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ??
            0C 02 17 7D ?? ?? ?? ?? 02 16 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 1A 8D ?? ?? ?? ?? 25
            16 03 8C ?? ?? ?? ?? A2 25 17 04 8C ?? ?? ?? ?? A2 25 18 05 8C ?? ?? ?? ?? A2 25 19
            08 A2 6F ?? ?? ?? ?? 26 2A 02 7B ?? ?? ?? ?? 39 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ??
            ?? ?? ?? 0D 2B ?? 09 6F ?? ?? ?? ?? 74 ?? ?? ?? ?? 13 ?? 02 11 ?? 16 9A A5 ?? ?? ??
            ?? 11 ?? 17 9A A5 ?? ?? ?? ?? 11 ?? 18 9A A5 ?? ?? ?? ?? 11 ?? 19 9A 74 ?? ?? ?? ??
            28 ?? ?? ?? ?? 11 ?? 16 9A A5 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 03 04 11 ?? 19 9A 74
            ?? ?? ?? ?? 18 73 ?? ?? ?? ?? 16 28 ?? ?? ?? ?? 26 09 6F ?? ?? ?? ?? 2D ?? DE ?? 09
            75 ?? ?? ?? ?? 13 ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 02 7B ?? ?? ?? ?? 6F ?? ??
            ?? ?? 28 ?? ?? ?? ?? 0A 02 03 04 05 06 28
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            (
                $get_tcp_connections
            ) or
            (
                all of ($get_operating_system_information_p*)
            ) or          
            (
                $take_screenshot
            ) or
            (
                $get_passwords
            ) or
            (
                $process_key_action
            )
        )
}
