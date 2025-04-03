rule MassLogger
{
    meta:
        id = "4ACUGiNEkzwhwoNl3ZrbkY"
        fingerprint = "v1_sha256_c8d82694810aafbdc6a35a661e7431e9536035e2f7fef90b9359064c4209b66c"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "MassLogger"
        category = "INFO"
        cape_type = "MassLogger Payload"

    strings:
        $name = "MassLogger"
        $fody = "Costura"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
