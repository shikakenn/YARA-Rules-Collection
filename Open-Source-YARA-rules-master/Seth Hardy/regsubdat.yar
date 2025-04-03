private rule RegSubDatCode : RegSubDat Family 
{
    meta:
        id = "6AUP8EKSAh0w2Q6b8xDXei"
        fingerprint = "v1_sha256_16f739e8ab2b77ac26e50bcd74e00ed454227895f002aa1a1f61a6ccc37147a6"
        version = "1.0"
        modified = "2014-07-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "RegSubDat code features"
        category = "INFO"

    strings:
        // decryption loop
        $ = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
        // push then pop values
        $ = { 68 FF FF 7F 00 5? }
        $ = { 68 FF 7F 00 00 5? }
    
    condition:
        all of them
}

private rule RegSubDatStrings : RegSubDat Family
{
    meta:
        id = "23zAetyn9i70VTnEGZfNhS"
        fingerprint = "v1_sha256_b4a763b79c30ae792f22b7c3c1704b11a7b9270a83c2b831fcde0fdeda27ca54"
        version = "1.0"
        modified = "2014-07-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "RegSubDat Identifying Strings"
        category = "INFO"

    strings:
        $avg1 = "Button"
        $avg2 = "Allow"
        $avg3 = "Identity Protection"
        $avg4 = "Allow for all"
        $avg5 = "AVG Firewall Asks For Confirmation"
        $mutex = "0x1A7B4C9F"
        
    condition:
       all of ($avg*) or $mutex
}

rule RegSubDat : Family
{
    meta:
        id = "6MlaDNy3p2UrRRxOQ87pJF"
        fingerprint = "v1_sha256_b52a350bf45003aebd7705e96910c3df9c509bcce76415286ccfec33161ad547"
        version = "1.0"
        modified = "2014-07-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "RegSubDat"
        category = "INFO"

    condition:
        RegSubDatCode or RegSubDatStrings
}
