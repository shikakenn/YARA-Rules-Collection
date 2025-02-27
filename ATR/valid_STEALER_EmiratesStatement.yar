rule STEALER_emirates_statement 
{
    meta:
        id = "2azUiwjiILm3DLfvTOPcNz"
        fingerprint = "v1_sha256_17eaddf375fc1875fb0275f8c0f93dfe921b452bdc6eb471adc155f749492328"
        version = "1.0"
        date = "2013-06-30"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Christiaan Beek | McAfee ATR Team"
        description = "Credentials Stealing Attack"
        category = "INFO"
        hash = "7cf757e0943b0a6598795156c156cb90feb7d87d4a22c01044499c4e1619ac57"
        rule_version = "v1"
        malware_family = "Stealer:W32/DarkSide"
        actor_group = "Unknown"

    strings:

        $string0 = "msn.klm"
        $string1 = "wmsn.klm"
        $string2 = "bms.klm"
    
    condition:
    
        all of them
}
