rule MALW_emotet
{
    meta:
        id = "1MF4JmJTDcSPJyXXIsSbb6"
        fingerprint = "v1_sha256_223e4453a6c3b56b0bc0f91147fa55ea59582d64b8a5c08f1f8d06026044065e"
        version = "1.0"
        date = "2020-07-21"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect unpacked Emotet"
        category = "INFO"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Emotet"
        hash1 = "a6621c093047446e0e8ae104769af93a5a8ed147ab8865afaafbbd22adbd052d"
        actor_group = "Unknown"

    strings:

        $pattern_0 = { 8b45fc 8be5 5d c3 55 8bec }
        $pattern_1 = { 3c39 7e13 3c61 7c04 3c7a 7e0b 3c41 }
        $pattern_2 = { 7c04 3c39 7e13 3c61 7c04 3c7a 7e0b }
        $pattern_3 = { 5f 8bc6 5e 5b 8be5 }
        $pattern_4 = { 5f 668906 5e 5b }
        $pattern_5 = { 3c30 7c04 3c39 7e13 3c61 7c04 }
        $pattern_6 = { 53 56 57 8bfa 8bf1 }
        $pattern_7 = { 3c39 7e13 3c61 7c04 3c7a 7e0b }
        $pattern_8 = { 55 8bec 83ec14 53 }
        $pattern_9 = { 5e 8be5 5d c3 55 8bec }
   
    condition:

        7 of them and filesize < 180224
}
