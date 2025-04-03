rule Varenyky
{
    meta:
        id = "4lc0dkbiErOmcURKNDFqIW"
        fingerprint = "v1_sha256_602f1b8b60b29565eabe2171fde4eb58546af68f8acecad402a7a51ea9a08ed9"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Varenyky Payload"
        category = "INFO"
        cape_type = "Varenyky Payload"

    strings:
        $onion = "jg4rli4xoagvvmw47fr2bnnfu7t2epj6owrgyoee7daoh4gxvbt3bhyd.onion"
    condition:
        uint16(0) == 0x5A4D and ($onion)
}
