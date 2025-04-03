rule TSCookie
{
    meta:
        id = "6xRxCPXtfixT7Y0LlI1VBn"
        fingerprint = "v1_sha256_0461c7fd14c74646437654f0a63a4a89d4efad620e197a8ca1e8d390618842c3"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "TSCookie Payload"
        category = "INFO"
        cape_type = "TSCookie Payload"

    strings:
        $string1 = "http://%s:%d" wide
        $string2 = "/Default.aspx" wide
        $string3 = "\\wship6"
    condition:
        uint16(0) == 0x5A4D and all of them
}
