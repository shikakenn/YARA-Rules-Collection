private rule MirageStrings : Mirage Family
{
    meta:
        id = "5cr22U7chXEZhMAKYMD5Az"
        fingerprint = "v1_sha256_9d8c6e6563de695807ffb0aac4798cf24c25a53a84808862bbc7722b513ff360"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Mirage Identifying Strings"
        category = "INFO"

    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
       any of them
}

rule Mirage : Family
{
    meta:
        id = "1EQVw6v6aXch5DihqzyWoX"
        fingerprint = "v1_sha256_4a78f5d3521d968f88339b71d0c92a30ea44c61cabda37d6e47904e3f9293717"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Mirage"
        category = "INFO"

    condition:
        MirageStrings
}
