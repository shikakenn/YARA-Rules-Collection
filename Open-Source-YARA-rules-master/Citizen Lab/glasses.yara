private rule GlassesCode : Glasses Family 
{
    meta:
        id = "54cSPeZsAKqVDL7rSCvYiI"
        fingerprint = "v1_sha256_28083849a02f058346652da35078fc53df8f72ac3e41ed82b9352834d70a4ebd"
        version = "1.0"
        modified = "2014-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Glasses code features"
        category = "INFO"

    strings:
        $ = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
        $ = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }
        
    condition:
        any of them
}

private rule GlassesStrings : Glasses Family
{
    meta:
        id = "4pQ6DEYcq3o2fVM7nTCdHz"
        fingerprint = "v1_sha256_968013a8b3ba576a641a9260539e3c5ca40a14b8902903ada3d33f32931b0b01"
        version = "1.0"
        modified = "2014-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Strings used by Glasses"
        category = "INFO"

    strings:
        $ = "thequickbrownfxjmpsvalzydg"
        $ = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0; %s.%s)"
        $ = "\" target=\"NewRef\"></a>"
 
    condition:
        all of them

}

rule Glasses : Family
{
    meta:
        id = "4XQCvyBQTYIeijVJ4KZdm"
        fingerprint = "v1_sha256_152f110049ed776705abd1abc543d6b58182b55c1ae256baf53f53dc0f2ef21e"
        version = "1.0"
        modified = "2014-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Glasses family"
        category = "INFO"

    condition:
        GlassesCode or GlassesStrings
        
}
