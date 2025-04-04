rule RANSOM_makop
{
    meta:
        id = "2iuds6hn8voRs4RijJLtXK"
        fingerprint = "v1_sha256_2b4f8b90d46530421b66dbb04df6e84d268709fbee884536d8acc91e1b85f8a4"
        version = "1.0"
        date = "2020-07-19"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the unpacked Makop ransomware samples"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        hash = "008e4c327875110b96deef1dd8ef65cefa201fef60ca1cbb9ab51b5304e66fe1"
        rule_version = "v1"
        malware_family = "Ransom:W32/Makop"
        actor_group = "Unknown"

    strings:

        $pattern_0 = { 50 8d7c2420 e8???????? 84c0 0f84a6020000 8b742460 ba???????? }
        $pattern_1 = { 51 52 53 ffd5 85c0 746d 8b4c240c }
        $pattern_2 = { 7521 68000000f0 6a18 6a00 6a00 56 ff15???????? }
        $pattern_3 = { 83c40c 8d4e0c 51 66c7060802 66c746041066 c6460820 }
        $pattern_4 = { 51 ffd3 50 ffd7 8b4628 85c0 }
        $pattern_5 = { 85c9 741e 8b4508 8b4d0c 8a11 }
        $pattern_6 = { 83c002 6685c9 75f5 2bc6 d1f8 66390c46 8d3446 }
        $pattern_7 = { 895a2c 8b7f04 85ff 0f85f7feffff 55 6a00 }
        $pattern_8 = { 8b3d???????? 6a01 6a00 ffd7 50 ff15???????? }
        $pattern_9 = { 85c0 7407 50 ff15???????? }
   
    condition:

        7 of them and
        filesize < 237568
}
