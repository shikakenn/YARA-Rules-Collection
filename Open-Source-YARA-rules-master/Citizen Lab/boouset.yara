private rule BoousetCode : Boouset Family 
{
    meta:
        id = "7H0Zqjyw63Y9pgYVInEDaN"
        fingerprint = "v1_sha256_d1591de63b5ff8b7deecc3a74f9be7b682072c3d8a2bbe7b00ca4a6d6a96c7e6"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Boouset code tricks"
        category = "INFO"

    strings:
        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }
        
    condition:
        any of them
}

private rule BoousetStrings : Boouset Family
{
    meta:
        id = "4Tkf64adLqu1TAanmPuMyf"
        fingerprint = "v1_sha256_73426a56460dc2f6bc35f1c85f942950b1dba745a2c320530c7685df2ac4c694"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Boouset Identifying Strings"
        category = "INFO"

    strings:
        $ = "Q\x00\x00\x00\x00W\x00\x00\x00\x00E\x00\x00\x00\x00R\x00\x00\x00\x00T\x00\x00\x00\x00Y\x00\x00\x00\x00"
        $ = "A\x00\x00\x00\x00S\x00\x00\x00\x00D\x00\x00\x00\x00F\x00\x00\x00\x00G\x00\x00\x00\x00H"
        $ = "Z\x00\x00\x00\x00X\x00\x00\x00\x00C\x00\x00\x00\x00V\x00\x00\x00\x00B\x00\x00\x00\x00N\x00\x00\x00\x00"
        $ = "\\~Z8314.tmp"
        $ = "hulee midimap" wide ascii
        
    condition:
       any of them
}

rule Boouset : Family
{
    meta:
        id = "3SAhEIdZeL9NW826CeaH3A"
        fingerprint = "v1_sha256_e8721afacc14d03263af43c84c43d5cdf8671a956327a8e0ecf140480794f172"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Boouset"
        category = "INFO"

    condition:
        BoousetCode or BoousetStrings
}
