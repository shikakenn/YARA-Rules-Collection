private rule SurtrCode : Surtr Family {
    meta:
        id = "2T2Fk4B7jq26UIUHSDiUAv"
        fingerprint = "v1_sha256_15303347f81703245a28ced7d5e14ae19f17ca3183ec8dd592ce45b0e9b4a7b1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Code features for Surtr Stage1"
        category = "INFO"
        last_updated = "2014-07-16"

    strings:
        //decrypt config
        $ = { 8A ?? ?? 84 ?? ?? 74 ?? 3C 01 74 ?? 34 01 88 41 3B ?? 72 ?? }
        //if Burn folder name is not in strings
        $ = { C6 [3] 42 C6 [3] 75 C6 [3] 72 C6 [3] 6E C6 [3] 5C }
        //mov char in _Fire
        $ = { C6 [3] 5F C6 [3] 46 C6 [3] 69 C6 [3] 72 C6 [3] 65 C6 [3] 2E C6 [3] 64 }

    condition:
        any of them

}

private rule SurtrStrings : Surtr Family {	
    meta:
        id = "5XYSsUH5OW1VZrB9qdJxDN"
        fingerprint = "v1_sha256_8c974e61dbcc682bd63a5d5b30e5bd44769a52d2289a8cabbd6cd3f6c69b5d0a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Strings for Surtr"
        category = "INFO"
        last_updated = "2014-07-16"

    strings:
        $ = "\x00soul\x00"
        $ = "\x00InstallDll.dll\x00"
        $ = "\x00_One.dll\x00"
        $ = "_Fra.dll"
        $ = "CrtRunTime.log"
        $ = "Prod.t"
        $ = "Proe.t"
        $ = "Burn\\"
        $ = "LiveUpdata_Mem\\"

    condition:
        any of them

}

rule Surtr : Family {
    meta:
        id = "2Ygg9UDetnQmTRDuFaWO5"
        fingerprint = "v1_sha256_7c5a37b2f93b1a5735683e32d33fc4d887e7b1235ec76139316b6c85c10fc46a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Rule for Surtr Stage One"
        category = "INFO"
        last_updated = "2014-07-16"

    condition:
        SurtrStrings or SurtrCode

}
