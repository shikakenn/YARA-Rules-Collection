private rule XtremeRATCode : XtremeRAT Family 
{
    meta:
        id = "62Q5f3ymxG4MS9G9GsWKUF"
        fingerprint = "v1_sha256_f36e121c5188fe8034bf627bac7e980fd2bc5e4030629c8a9070bd4cc6a89b09"
        version = "1.0"
        modified = "2014-07-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "XtremeRAT code features"
        category = "INFO"

    strings:
        // call; fstp st
        $ = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $ = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
    
    condition:
        all of them
}

private rule XtremeRATStrings : XtremeRAT Family
{
    meta:
        id = "2SGcO1IU0kvZSo6PzId3Tn"
        fingerprint = "v1_sha256_8dbee9c3f19a70a6c0d0ca3afed69d1e2be5fe84e5a79897c49471b23569d6cc"
        version = "1.0"
        modified = "2014-07-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "XtremeRAT Identifying Strings"
        category = "INFO"

    strings:
        $ = "dqsaazere"
        $ = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       any of them
}

rule XtremeRAT : Family
{
    meta:
        id = "2L42Nu8i7HsoId0uNES0LO"
        fingerprint = "v1_sha256_21dca9ace430a7f6394fa9b8e4bae83d1ba3adb23db6096af20cdcb45692e7c2"
        version = "1.0"
        modified = "2014-07-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "XtremeRAT"
        category = "INFO"

    condition:
        XtremeRATCode or XtremeRATStrings
}
