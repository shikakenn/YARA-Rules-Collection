private rule ScarhiknCode : Scarhikn Family 
{
    meta:
        id = "5DAAymi8EaeVbLfwdSgd3V"
        fingerprint = "v1_sha256_5f1a07ec221fa9f8a454b9314776480376e016c3e223167fc322f6c639af7efe"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Scarhikn code features"
        category = "INFO"

    strings:
        // decryption
        $ = { 8B 06 8A 8B ?? ?? ?? ?? 30 0C 38 03 C7 55 43 E8 ?? ?? ?? ?? 3B D8 59 72 E7 }
        $ = { 8B 02 8A 8D ?? ?? ?? ?? 30 0C 30 03 C6 8B FB 83 C9 FF 33 C0 45 F2 AE F7 D1 49 3B E9 72 E2 }
    
    condition:
        any of them
}

private rule ScarhiknStrings : Scarhikn Family
{
    meta:
        id = "4vcYVEl4RjyEdAoPzyr3Ex"
        fingerprint = "v1_sha256_3a794572be3e97f3eb1e42745239717f31c6f7a8284935d42f6d16e8204c2d02"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Scarhikn Identifying Strings"
        category = "INFO"

    strings:
        $ = "9887___skej3sd"
        $ = "haha123"
        
    condition:
       any of them
}

rule Scarhikn : Family
{
    meta:
        id = "3U0HLReI70otIKS1ULKMow"
        fingerprint = "v1_sha256_539b98c40c373f2fe445d17d46eb7b1a0179d027fc9d1f23c3bcdb06231c8800"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Scarhikn"
        category = "INFO"

    condition:
        ScarhiknCode or ScarhiknStrings
}
