rule Stealc
{
    meta:
        id = "S31c5vSMJ3bOmbK6CbR6D"
        fingerprint = "v1_sha256_a6165168b7c74761b91d1691465688c748227b830813067edb4e9bdc934271c4"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Stealc Payload"
        category = "INFO"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
        cape_type = "Stealc Payload"

    strings:
        $nugget1 = {68 04 01 00 00 6A 00 FF 15 [4] 50 FF 15}
        $nugget2 = {64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC}
    condition:
        uint16(0) == 0x5A4D and all of them
}
