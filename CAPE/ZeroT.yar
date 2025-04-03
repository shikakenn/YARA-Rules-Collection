rule ZeroT
{
    meta:
        id = "pQYwyg88wgNBvJDyOz0IR"
        fingerprint = "v1_sha256_f60ae25ac3cd741b8bdc5100b5d3c474b5d9fbe8be88bfd184994bae106c3803"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "ZeroT Payload"
        category = "INFO"
        cape_type = "ZeroT Payload"

    strings:
        $decrypt = {8B C1 8D B5 FC FE FF FF 33 D2 03 F1 F7 75 10 88 0C 33 41 8A 04 3A 88 06 81 F9 00 01 00 00 7C E0}
        $string1 = "(*^GF(9042&*"
        $string2 = "s2-18rg1-41g3j_.;"
        $string3 = "GET" wide
        $string4 = "open"
    condition:
        uint16(0) == 0x5A4D and all of them
}
