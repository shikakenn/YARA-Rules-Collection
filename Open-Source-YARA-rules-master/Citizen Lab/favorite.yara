private rule FavoriteCode : Favorite Family 
{
    meta:
        id = "1qyKse7Z0MzZ1ZXugI6JP3"
        fingerprint = "v1_sha256_ae8ea3095da4f7921bb59385c49c6ea40e17a42b15836b85d7656ffd343bf42f"
        version = "1.0"
        modified = "2014-06-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Favorite code features"
        category = "INFO"

    strings:
        // standard string hiding
        $ = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
        $ = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }
    
    condition:
        any of them
}

private rule FavoriteStrings : Favorite Family
{
    meta:
        id = "79wgbUTZDm4BOS4utz46n0"
        fingerprint = "v1_sha256_a147aeab92445dc602ed013aa896ce59cd592c810d001593cf7656a05510fad5"
        version = "1.0"
        modified = "2014-06-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Favorite Identifying Strings"
        category = "INFO"

    strings:
        $string1 = "!QAZ4rfv"
        $file1 = "msupdater.exe"
        $file2 = "FAVORITES.DAT"
        
    condition:
       any of ($string*) or all of ($file*)
}

rule Favorite : Family
{
    meta:
        id = "3p3bqWgcEnt8rpZqRldlEo"
        fingerprint = "v1_sha256_81e59856af0c8553e2a18c7a1e2d2b634ff90f1d6c00130e294fa072dc19f094"
        version = "1.0"
        modified = "2014-06-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Favorite"
        category = "INFO"

    condition:
        FavoriteCode or FavoriteStrings
}
