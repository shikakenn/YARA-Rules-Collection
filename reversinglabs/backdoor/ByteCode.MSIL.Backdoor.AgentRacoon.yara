rule ByteCode_MSIL_Backdoor_AgentRacoon: tc_detection malicious
{
    meta:
        id = "5iWf1fYYtw8NiVZVBc7SHh"
        fingerprint = "v1_sha256_3ba73f19f59c2e5880df820c52f16997047d7299eb14d421ae2ed8f3790bcfe9"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects AgentRacoon backdoor."
        category = "MALWARE"
        malware = "AGENTRACOON"
        tc_detection_type = "Backdoor"
        tc_detection_name = "AgentRacoon"
        tc_detection_factor = 5

    strings:

        $unpack_response_p1 = {
            17 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 03 18 91 9C 11 ?? 73 ?? ?? ?? ?? 0A 06 16 6F ?? ??
            ?? ?? 2D ?? 73 ?? ?? ?? ?? 7A 17 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 03 19 91 9C 11 ?? 73
            ?? ?? ?? ?? 0A 06 1A 6F ?? ?? ?? ?? 2C ?? 06 1B 6F ?? ?? ?? ?? 2C ?? 06 1C 6F ?? ??
            ?? ?? 2C ?? 06 1D 6F ?? ?? ?? ?? 2C ?? 73 ?? ?? ?? ?? 7A 1F ?? 0B 2B ?? 07 17 58 0B
            03 07 91 2D ?? 07 17 58 0B 03 8E 69 07 59 0C 08 8D ?? ?? ?? ?? 0D 03 07 09 16 08 28
            ?? ?? ?? ?? 1A 13 ?? 2B ?? 11 ?? 17 58 13 ?? 09 11 ?? 91 2D ?? 11 ?? 17 58 13 ?? 09
            8E 69 11 ?? 59 0C 08 8D ?? ?? ?? ?? 13 ?? 09 11 ?? 11 ?? 16 08 28 ?? ?? ?? ?? 02 12
            ?? FE 15 ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ??
            7D ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ??
            ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ??
            ?? 12 ?? 07 1F ?? 59 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ??
            ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 12 ?? 11 ?? 1A 59 8D ?? ?? ?? ?? 7D ??
            ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ??
            ?? 12 ?? 1A 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 12 ?? 18 8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 11
            ?? 7D ?? ?? ?? ?? 03 16 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ?? ?? ?? ?? 03 18
        }

        $unpack_response_p2 = {
            02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ?? ?? ?? ?? 03 1A 02 7C ?? ?? ?? ?? 7B ??
            ?? ?? ?? 16 18 28 ?? ?? ?? ?? 03 1C 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ?? ??
            ?? ?? 03 1E 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ?? ?? ?? ?? 03 1F ?? 02 7C ??
            ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ?? ?? ?? ?? 03 1F ?? 02 7C ?? ?? ?? ?? 7B ?? ?? ??
            ?? 16 07 1F ?? 59 28 ?? ?? ?? ?? 09 16 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ??
            ?? ?? ?? 09 18 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ?? ?? ?? ?? 09 1A 02 7C ??
            ?? ?? ?? 7B ?? ?? ?? ?? 16 11 ?? 1A 59 28 ?? ?? ?? ?? 11 ?? 16 02 7C ?? ?? ?? ?? 7B
            ?? ?? ?? ?? 16 18 28 ?? ?? ?? ?? 11 ?? 18 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28
            ?? ?? ?? ?? 11 ?? 1A 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 1A 28 ?? ?? ?? ?? 11 ?? 1E
            02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 18 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 2C ?? 02 7C ??
            ?? ?? ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 1F ?? 91 13 ?? 02 7C ?? ?? ?? ?? 11 ??
            8D ?? ?? ?? ?? 7D ?? ?? ?? ?? 11 ?? 1F ?? 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 16 11 ??
            28 ?? ?? ?? ?? 2A
        }

        $upload = {
            28 ?? ?? ?? ?? 0A 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 2D ?? DD ?? ?? ?? ?? 16 0B 38 ??
            ?? ?? ?? 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 0C 06 02 7C ?? ?? ?? ??
            7B ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 08 28 ?? ?? ?? ?? 02 7C ?? ?? ?? ??
            7B ?? ?? ?? ?? 1B 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 72 ?? ?? ?? ?? A2 11 ?? 17 02 7C ??
            ?? ?? ?? 7B ?? ?? ?? ?? 07 6F ?? ?? ?? ?? A2 11 ?? 18 72 ?? ?? ?? ?? A2 11 ?? ?? 06
            A2 11 ?? 1A 72 ?? ?? ?? ?? A2 11 ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7C ?? ?? ?? ??
            7B ?? ?? ?? ?? 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 07
            14 6F ?? ?? ?? ?? 07 17 58 0B 07 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 3F
            ?? ?? ?? ?? 02 7C ?? ?? ?? ?? 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7C ?? ?? ?? ?? 73 ??
            ?? ?? ?? 7D ?? ?? ?? ?? DE 23 0D 02 7C ?? ?? ?? ?? 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 09
            6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 2A
        }

        $perform_request = {
            05 6F ?? ?? ?? ?? 0A 06 04 3D ?? ?? ?? ?? 06 04 19 5B 18 5A 3F ?? ?? ?? ?? 05 16 06
            19 5B 6F ?? ?? ?? ?? 0B 05 06 19 5B 06 19 5B 6F ?? ?? ?? ?? 0C 05 06 19 5B 18 5A 6F
            ?? ?? ?? ?? 0D 02 07 28 ?? ?? ?? ?? 0B 02 08 28 ?? ?? ?? ?? 0C 02 09 28 ?? ?? ?? ??
            0D 1F ?? 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 03 A2 11 ?? 17 72 ?? ?? ?? ?? A2 11 ?? 18 07
            A2 11 ?? 19 72 ?? ?? ?? ?? A2 11 ?? 1A 08 A2 11 ?? 1B 72 ?? ?? ?? ?? A2 11 ?? 1C 09
            A2 11 ?? 1D 72 ?? ?? ?? ?? A2 11 ?? 1E 02 28 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ??
            ?? A2 11 ?? 1F ?? 02 7B ?? ?? ?? ?? A2 11 ?? 28 ?? ?? ?? ?? 10 ?? 38 ?? ?? ?? ?? 06
            04 19 5B 18 5A 3D ?? ?? ?? ?? 06 04 19 5B 3F ?? ?? ?? ?? 05 16 06 18 5B 6F ?? ?? ??
            ?? 13 ?? 05 06 18 5B 6F ?? ?? ?? ?? 13 ?? 02 11 ?? 28 ?? ?? ?? ?? 13 ?? 02 11 ?? 28
            ?? ?? ?? ?? 13 ?? 1F ?? 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 03 A2 11 ?? 17 72 ?? ?? ?? ??
            A2 11 ?? 18 11 ?? A2 11 ?? 19 72 ?? ?? ?? ?? A2 11 ?? 1A 11 ?? A2 11 ?? 1B 72 ?? ??
            ?? ?? A2 11 ?? 1C 02 28 ?? ?? ?? ?? A2 11 ?? 1D 72 ?? ?? ?? ?? A2 11 ?? 1E 02 7B ??
            ?? ?? ?? A2 11 ?? 28 ?? ?? ?? ?? 10 ?? 2B ?? 02 05 28 ?? ?? ?? ?? 13 ?? 1D 8D ?? ??
            ?? ?? 13 ?? 11 ?? 16 03 A2 11 ?? 17 72 ?? ?? ?? ?? A2 11 ?? 18 11 ?? A2 11 ?? 19 72
            ?? ?? ?? ?? A2 11 ?? 1A 02 28 ?? ?? ?? ?? A2 11 ?? 1B 72 ?? ?? ?? ?? A2 11 ?? 1C 02
            7B ?? ?? ?? ?? A2 11 ?? 28 ?? ?? ?? ?? 10 ?? 05 2A
        }

        $get_txt_record = {
            14 0A 03 73 ?? ?? ?? ?? 0B 07 6F ?? ?? ?? ?? 0C 7E ?? ?? ?? ?? 1F ?? 73 ?? ?? ?? ??
            0D 09 08 08 8E 69 6F ?? ?? ?? ?? 26 09 6F ?? ?? ?? ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ??
            09 12 ?? 6F ?? ?? ?? ?? 13 ?? 09 6F ?? ?? ?? ?? 07 11 ?? 6F ?? ?? ?? ?? 07 6F ?? ??
            ?? ?? 13 ?? 28 ?? ?? ?? ?? 12 ?? 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? DE ?? 26 72 ??
            ?? ?? ?? 13 ?? DE ?? 11 ?? 2A
        }

        $main_loop = {
            73 ?? ?? ?? ?? 80 ?? ?? ?? ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 73 ?? ?? ?? ?? 80 ?? ??
            ?? ?? 73 ?? ?? ?? ?? 80 ?? ?? ?? ?? 7E ?? ?? ?? ?? 18 16 16 6F ?? ?? ?? ?? 0A 06 28
            ?? ?? ?? ?? 2D ?? 2A 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 2A 7E ?? ??
            ?? ?? 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 07 6F ?? ?? ??
            ?? 6F ?? ?? ?? ?? 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C 12 ?? 7B ?? ?? ?? ?? 0D 12 ?? 7B
            ?? ?? ?? ?? 13 ?? 72 ?? ?? ?? ?? 13 ?? 16 13 ?? 2B ?? 7E ?? ?? ?? ?? 19 11 ?? 11 ??
            6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 2D ?? 14 80 ?? ?? ?? ?? 2A 11 ?? 7E ?? ?? ?? ?? 28 ??
            ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ??
            ?? ?? 11 ?? 17 58 13 ?? 11 ?? 09 32 ?? 7E ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 0B 73 ??
            ?? ?? ?? 80 ?? ?? ?? ?? 7E ?? ?? ?? ?? 7E ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 6F ?? ?? ??
            ?? 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? 7E ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 7E ?? ?? ?? ?? 07
            17 6F ?? ?? ?? ?? 13 ?? 11 ?? 7E ?? ?? ?? ?? 1A 16 16 6F ?? ?? ?? ?? 6F ?? ?? ?? ??
            11 ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 DD ?? ?? ?? ?? 26 DE ?? 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($unpack_response_p*)
        ) and
        (
            $upload
        ) and
        (
            $perform_request
        ) and
        (
            $get_txt_record
        ) and
        (
            $main_loop
        )
}
