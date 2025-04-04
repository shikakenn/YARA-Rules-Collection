rule CobaltStrikeStager
{
    meta:
        id = "6qlbXzTKxcRa9eFnSB2lK7"
        fingerprint = "v1_sha256_6a55b0c3ab5f557dfb7a3f8bd616ede1bd9b93198590fc9d52aa19c1154388c5"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dan__mayer <daniel@stairwell.com>"
        description = "Cobalt Strike Stager Payload"
        category = "INFO"
        cape_type = "CobaltStrikeStager Payload"

    strings:
        $smb = { 68 00 B0 04 00 68 00 B0 04 00 6A 01 6A 06 6A 03 52 68 45 70 DF D4 }
        $http_x86 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
        $http_x64 = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 49 89 E6 4C 89 F1 41 BA 4C 77 26 07 }
        $dns = { 68 00 10 00 00 68 FF FF 07 00 6A 00 68 58 A4 53 E5 }

    condition:
        any of them
}
