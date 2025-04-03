rule Gootkit
{
    meta:
        id = "13cMRC0Ju9SVuWhZYuN1yU"
        fingerprint = "v1_sha256_26704b6b0adca51933fc9d5e097930320768fd0e9355dcefc725aee7775316e7"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Gootkit Payload"
        category = "INFO"
        cape_type = "Gootkit Payload"

    strings:
        $code1 = {C7 45 ?? ?? ?? 4? 00 C7 45 ?? ?? 10 40 00 C7 45 E? D8 ?? ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 [1-2] 00 10 40 00 89 [5-6] 43 00 89 ?? ?? 68 E8 80 00 00 FF 15}
    condition:
        uint16(0) == 0x5A4D and all of them
}
