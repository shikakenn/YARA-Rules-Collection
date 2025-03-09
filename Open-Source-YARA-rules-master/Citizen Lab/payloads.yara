rule XYPayload : Payload
{
    meta:
        id = "61G3GOrD0Fphg6fCHizv2b"
        fingerprint = "v1_sha256_cc29adc2524cf9b5c19e0a4941e1ecfdc8c50cfbbdf65d76cceb6fd50fe37022"
        version = "1.0"
        modified = "2014-05-05"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Identifier for payloads using XXXXYYYY/YYYYXXXX markers"
        category = "INFO"

    strings:
        $start_marker = "XXXXYYYY"
        $end_marker = "YYYYXXXX"
    
    condition:
        $start_marker and $end_marker
}
