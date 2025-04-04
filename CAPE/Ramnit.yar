rule Ramnit
{
    meta:
        id = "4Yw2wc5elDx6tNBU0mDtYG"
        fingerprint = "v1_sha256_6f661f47bdf8377b0fb96f190fcb964c0ed2b43ce7ae7880f9dfce9e43837efd"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Ramnit Payload"
        category = "INFO"
        cape_type = "Ramnit Payload"

    strings:
        $DGA = {33 D2 B9 1D F3 01 00 F7 F1 8B C8 B8 A7 41 00 00 F7 E2 8B D1 8B C8 B8 14 0B 00 00 F7 E2 2B C8 33 D2 8B C1 8B}
        $xor_loop = {83 7D 0C 00 74 27 83 7D 14 00 74 21 8B 4D 0C 8B 7D 08 8B 75 10 BA 00 00 00 00 0B D2 75 04 8B 55 14 4A 8A 1C 32 32 1F 88 1F 47 4A E2 ED}
        $id_string = "{%08X-%04X-%04X-%04X-%08X%04X}"
    condition:
        uint16(0) == 0x5A4D and all of ($*)
}
