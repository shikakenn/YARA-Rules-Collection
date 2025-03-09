private rule RooterCode : Rooter Family 
{
    meta:
        id = "1DLwayZjlVXiV61Ez2sGKi"
        fingerprint = "v1_sha256_d0fba77f718fcf0b791ad7333b48d7c7f22b9eb17c21a2a8e9a526be456d2b48"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Rooter code features"
        category = "INFO"

    strings:
        // xor 0x30 decryption
        $ = { 80 B0 ?? ?? ?? ?? 30 40 3D 00 50 00 00 7C F1 }
    
    condition:
        any of them
}

private rule RooterStrings : Rooter Family
{
    meta:
        id = "6HUn8FeiBo0EtXIsiTQP19"
        fingerprint = "v1_sha256_90613d36365c66c163ae5cca34f30e022e61f4e0082dfc8a4892cbc86ae625c7"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Rooter Identifying Strings"
        category = "INFO"

    strings:
        $group1 = "seed\x00"
        $group2 = "prot\x00"
        $group3 = "ownin\x00"
        $group4 = "feed0\x00"
        $group5 = "nown\x00"

    condition:
       3 of ($group*)
}

rule Rooter : Family
{
    meta:
        id = "3pv8qH7zPDe370bIh65dMl"
        fingerprint = "v1_sha256_525f217c20dca41d2b9ec180025ec716cacaee9d1df9ff085947d7d3dfaaae24"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Rooter"
        category = "INFO"

    condition:
        RooterCode or RooterStrings
}
