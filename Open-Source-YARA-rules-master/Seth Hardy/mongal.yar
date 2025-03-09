private rule MongalCode : Mongal Family 
{
    meta:
        id = "3up29BIpZvtkb6bLn0sglp"
        fingerprint = "v1_sha256_5b630cc1faeee6e5d1629910e037a49487797fa9ff6f99a32a91b2fcbab10021"
        version = "1.0"
        modified = "2014-07-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Mongal code features"
        category = "INFO"

    strings:
        // gettickcount value checking
        $ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }
        
    condition:
        any of them
}

private rule MongalStrings : Mongal Family
{
    meta:
        id = "39VS2WyODaTfbMKIMFHQek"
        fingerprint = "v1_sha256_240c570064c781398aa570b10a321fe46d96c7bd3c52be434555dca762482cc7"
        version = "1.0"
        modified = "2014-07-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Mongal Identifying Strings"
        category = "INFO"

    strings:
        $ = "NSCortr.dll"
        $ = "NSCortr1.dll"
        $ = "Sina.exe"
        
    condition:
        any of them
}

rule Mongal : Family
{
    meta:
        id = "SRShKZoaP3l4XmdQo0pu1"
        fingerprint = "v1_sha256_87d0a6eeec106b2374ef0e450e6ad981b1d6c355af52667d4209541e205b582c"
        version = "1.0"
        modified = "2014-07-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Mongal"
        category = "INFO"

    condition:
        MongalCode or MongalStrings
}
