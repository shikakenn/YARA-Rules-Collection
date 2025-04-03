private rule PubSabCode : PubSab Family 
{
    meta:
        id = "3ihZoWywpaPGHGafqLqCii"
        fingerprint = "v1_sha256_7a50d4e4ab6e0158782f717e37d140b190e32a4d8a1d8f1dca9accb2badc225c"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "PubSab code tricks"
        category = "INFO"

    strings:
        $decrypt = { 6B 45 E4 37 89 CA 29 C2 89 55 E4 }
        
    condition:
        any of them
}

private rule PubSabStrings : PubSab Family
{
    meta:
        id = "78X4Lh1guErHJB4lSBAkfi"
        fingerprint = "v1_sha256_039017d70a13a7c0e852096b08619d7819e2e7679538979bc40765c4178ae828"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "PubSab Identifying Strings"
        category = "INFO"

    strings:
        $ = "_deamon_init"
        $ = "com.apple.PubSabAgent"
        $ = "/tmp/screen.jpeg"
       
    condition:
        any of them
}

rule PubSab : Family
{
    meta:
        id = "5NHaa1XjQWIzhhhMtntYHp"
        fingerprint = "v1_sha256_60f8f960de996e4263033621bcce774bc66f331d0ab8f76ea677a12f2a14a31c"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "PubSab"
        category = "INFO"

    condition:
        PubSabCode or PubSabStrings
}
