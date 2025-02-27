rule SmokeLoader
{
    meta:
        id = "LoQIg4c8vUbbvXFuGgrxI"
        fingerprint = "v1_sha256_779e2ac213e5ced7bc06e6208826b65cf8fc3113a69ede6408b84055542fa76d"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "SmokeLoader Payload"
        category = "INFO"
        cape_type = "SmokeLoader Payload"

    strings:
        $rc4_decrypt64 = {41 8D 41 01 44 0F B6 C8 42 0F B6 [2] 41 8D 04 12 44 0F B6 D0 42 8A [2] 42 88 [2] 42 88 [2] 42 0F B6 [2] 03 CA 0F B6 C1 8A [2] 30 0F 48 FF C7 49 FF CB 75}
        $rc4_decrypt32 = {47 B9 FF 00 00 00 23 F9 8A 54 [2] 0F B6 C2 03 F0 23 F1 8A 44 [2] 88 44 [2] 88 54 [2] 0F B6 4C [2] 0F B6 C2 03 C8 81 E1 FF 00 00 00 8A 44 [2] 30 04 2B 43 3B 9C 24 [4] 72 C0}
        $fetch_c2_64 = {74 ?? B? E8 03 00 00 B9 58 02 00 00 FF [5] 48 FF C? 75 F0 [6-10] 48 8D 05}
        $fetch_c2_32 = {8B 96 [2] (00|01) 00 8B CE 5E 8B 14 95 [4] E9}
    condition:
        2  of them
}
