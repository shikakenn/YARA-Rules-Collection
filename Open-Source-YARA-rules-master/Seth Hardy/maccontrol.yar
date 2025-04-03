private rule MacControlCode : MacControl Family 
{
    meta:
        id = "4ikwIaF9cj6Y6zRDoGvfHJ"
        fingerprint = "v1_sha256_d212c0762c2c4135c976b6969ccab11f82f2c61e4f51bb06eb37060982c3ecfb"
        version = "1.0"
        modified = "2014-06-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "MacControl code tricks"
        category = "INFO"

    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
        $L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
        $L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
        $L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
        $GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }
        
    condition:
        all of ($L4*) or $GEThgif
}

private rule MacControlStrings : MacControl Family
{
    meta:
        id = "2fx7uCHgYAxdtjAxg32UH"
        fingerprint = "v1_sha256_07be1815f37d8000596cc497bd5cd398f7e12cf409d0d150248cff083acbb3af"
        version = "1.0"
        modified = "2014-06-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "MacControl Identifying Strings"
        category = "INFO"

    strings:
        $ = "HTTPHeadGet"
        $ = "/Library/launched"
        $ = "My connect error with no ip!"
        $ = "Send File is Failed"
        $ = "****************************You Have got it!****************************"
        
    condition:
        any of them
}

rule MacControl : Family
{
    meta:
        id = "3o6fmPsA9VAB3jkMUI4NC5"
        fingerprint = "v1_sha256_df2693e3c85c8dcc5f833122f46feb239801b578dd6d39b8d4bd0c57c1d66576"
        version = "1.0"
        modified = "2014-06-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "MacControl"
        category = "INFO"

    condition:
        MacControlCode or MacControlStrings
}
