private rule WarpCode : Warp Family 
{
    meta:
        id = "6REnGMthdvnD3nYS7jSnPk"
        fingerprint = "v1_sha256_0356d42fb93235930670c10ef0fd2c902a8f60e588a5893dda94533ffe565d39"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Warp code features"
        category = "INFO"

    strings:
        // character replacement
        $ = { 80 38 2B 75 03 C6 00 2D 80 38 2F 75 03 C6 00 5F }
    
    condition:
        any of them
}

private rule WarpStrings : Warp Family
{
    meta:
        id = "1MnNskDY3keJLRQPvn7xGC"
        fingerprint = "v1_sha256_d9a8dfb6b86cc312d82ef636cdd2540744a3508886f448fc40b3dcb3afe98686"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Warp Identifying Strings"
        category = "INFO"

    strings:
        $ = "/2011/n325423.shtml?"
        $ = "wyle"
        $ = "\\~ISUN32.EXE"

    condition:
       any of them
}

rule Warp : Family
{
    meta:
        id = "6TS0OckVOQxomUQQBXg7Es"
        fingerprint = "v1_sha256_0a91d35de041d6135f29fbfbc63bdcda7478b98035217ed98630695e4c9cf299"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Warp"
        category = "INFO"

    condition:
        WarpCode or WarpStrings
}
