rule DoomedLoader
{
    meta:
        id = "135vPwcgPYHUpaDw1cFCE8"
        fingerprint = "v1_sha256_54a5962ef49ebf987908c4ea1559788f7c96a7e4ea61d2973636e998a0239c77"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "NA"
        category = "INFO"
        cape_type = "DoomedLoader Payload"
        packed = "914b1b3180e7ec1980d0bafe6fa36daade752bb26aec572399d2f59436eaa635"

    strings:
        $anti = {48 8B 4C 24 ?? E8 [4] 84 C0 B8 [4] 41 0F 45 C6 EB}
        $syscall = {49 89 CA 8B 44 24 08 FF 64 24 10}
    condition:
        uint16(0) == 0x5A4D and all of them
}
