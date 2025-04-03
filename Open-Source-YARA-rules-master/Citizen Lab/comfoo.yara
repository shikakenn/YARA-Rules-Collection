private rule ComfooCode : Comfoo Family 
{
    meta:
        id = "21FCBpU0TV0DIJZ11N1RRq"
        fingerprint = "v1_sha256_d5442a2ba9a32b81b507e87ce47571f0f8eb680c4d05fa45c4f6d938ffd550fc"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Comfoo code features"
        category = "INFO"

    strings:
        $resource = { 6A 6C 6A 59 55 E8 01 FA FF FF }
  
    condition:
        any of them
}

private rule ComfooStrings : Comfoo Family
{
    meta:
        id = "6Q4jQBxOVZqkOUzL02456y"
        fingerprint = "v1_sha256_9530163d0fe8bdf1fca550afb37434c06b78ad2bd9a759d84ff26a6829920f59"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Comfoo Identifying Strings"
        category = "INFO"

    strings:
        $ = "fefj90"
        $ = "iamwaitingforu653890"
        $ = "watchevent29021803"
        $ = "THIS324NEWGAME"
        $ = "ms0ert.temp"
        $ = "\\mstemp.temp"
        
    condition:
       any of them
}

rule Comfoo : Family
{
    meta:
        id = "6Ws7IY6XqUDfTPRdkAJHzs"
        fingerprint = "v1_sha256_bba13c40e6f2e749029a4c849595fca9d1bfdb6bdc7f95121227c7bc12a82d46"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Comfoo"
        category = "INFO"

    condition:
        ComfooCode or ComfooStrings
}
