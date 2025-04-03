rule Cryptoshield
{
    meta:
        id = "5cFXjsVEjcPbmtbQfgvzJX"
        fingerprint = "v1_sha256_46064b4c69cb1af01330c5d194ef50728e0f0479e9fbf72828822935f8e37ac6"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Cryptoshield Payload"
        category = "INFO"
        cape_type = "Cryptoshield Payload"

    strings:
        $a1 = "CRYPTOSHIELD." wide
        $a2 = "Click on Yes in the next window for restore work explorer" wide
        $a3 = "r_sp@india.com - SUPPORT"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
