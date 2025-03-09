rule YayihCode : Yayih Family 
{
    meta:
        id = "5cyynoyy5eCEDVqxzXu730"
        fingerprint = "v1_sha256_5d5a17375a49d45f45c9fd7dca288cb95c5882b7817682f7f40835b3a14478ae"
        version = "1.0"
        modified = "2014-07-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Yayih code features"
        category = "INFO"

    strings:
        //  encryption
        $ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }
    
    condition:
        any of them
}

rule YayihStrings : Yayih Family
{
    meta:
        id = "2VWrTJ7UgVrDvy5ao0m2lE"
        fingerprint = "v1_sha256_fa4236ca39d230a35d04a05951e12e54153a47e0784c3ef8f9759436a5a4ae73"
        version = "1.0"
        modified = "2014-07-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Yayih Identifying Strings"
        category = "INFO"

    strings:
        $ = "/bbs/info.asp"
        $ = "\\msinfo.exe"
        $ = "%s\\%srcs.pdf"
        $ = "\\aumLib.ini"

    condition:
       any of them
}

rule Yayih : Family
{
    meta:
        id = "35IgltlCMPxdC1FZSMU9Jy"
        fingerprint = "v1_sha256_ff1aabf2e456215b2121c2a7a513b4dfbc28c2caf8e471731692a9a3e787ea45"
        version = "1.0"
        modified = "2014-07-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Yayih"
        category = "INFO"

    condition:
        YayihCode or YayihStrings
}
