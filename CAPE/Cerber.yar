rule Cerber
{
    meta:
        id = "7ALygGyP211ClggKFSxlpm"
        fingerprint = "v1_sha256_16a8f808c28d3b142c079a305aba7f553f2452e439710bf610a06f8f2924d5a3"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Cerber Payload"
        category = "INFO"
        cape_type = "Cerber Payload"

    strings:
        $code1 = {33 C0 66 89 45 8? 8D 7D 8? AB AB AB AB AB [0-2] 66 AB 8D 45 8? [0-3] E8 ?? ?? 00 00}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}
