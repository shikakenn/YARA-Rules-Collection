rule ZeusPanda
{
    meta:
        id = "BY2XCWYIjdT80U10HM3xA"
        fingerprint = "v1_sha256_43d8a56cae9fd23c053f6956851734d3270b46a906236854502c136e3bb1e761"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "ZeusPanda Payload"
        category = "INFO"
        cape_type = "ZeusPanda Payload"

    strings:
        $code1 = {8B 01 57 55 55 55 55 55 55 53 51 FF 50 0C 85 C0 78 E? 55 55 6A 03 6A 03 55 55 6A 0A FF 37}
        $code2 = {8D 85 B0 FD FF FF 50 68 ?? ?? ?? ?? 8D 85 90 FA FF FF 68 0E 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 7E ?? 68 04 01 00 00 8D 85 B0 FD FF FF}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
