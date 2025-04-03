private rule LURK0Header : Family LURK0 {
    meta:
        id = "7dWoIisOU9VLFVYNydFZAi"
        fingerprint = "v1_sha256_3b485c7e059500ea6f017ea07363be13681df34323d5f7277154416f492f9b50"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "5 char code for LURK0"
        category = "INFO"
        last_updated = "07-21-2014"

    strings:
        $ = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }

    condition:
        any of them
}

private rule CCTV0Header : Family CCTV0 {
    meta:
        id = "NpX7y9rSxF2gTxtxJ2UJ0"
        fingerprint = "v1_sha256_0fee967053675366dfbe6d04ec5d6fa08bb9414effc7c84df1f3f8eb112d3f2a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "5 char code for LURK0"
        category = "INFO"
        last_updated = "07-21-2014"

    strings:
        //if its just one char a time
        $ = { C6 [5] 43 C6 [5] 43 C6 [5] 54 C6 [5] 56 C6 [5] 30 }
        // bit hacky but for when samples dont just simply mov 1 char at a time
        $ = { B0 43 88 [3] 88 [3] C6 [3] 54 C6 [3] 56 [0-12] (B0 30 | C6 [3] 30) }

    condition:
        any of them
}

private rule SharedStrings : Family {
    meta:
        id = "799quHuLOM7zuC7Q8c8iuv"
        fingerprint = "v1_sha256_8c8a8e854c20daecaa426459c07d7dad8ef71e173c78f68be5ac3a65eb3e0e78"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Internal names found in LURK0/CCTV0 samples"
        category = "INFO"
        last_updated = "07-22-2014"

    strings:
        // internal names
        $i1 = "Butterfly.dll"
        $i2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
        $i3 = "ETClientDLL"

        // dbx
        $d1 = "\\DbxUpdateET\\" wide
        $d2 = "\\DbxUpdateBT\\" wide
        $d3 = "\\DbxUpdate\\" wide
        
        // other folders
        $mc1 = "\\Micet\\"

        // embedded file names
        $n1 = "IconCacheEt.dat" wide
        $n2 = "IconConfigEt.dat" wide

        $m1 = "\x00\x00ERXXXXXXX\x00\x00" wide
        $m2 = "\x00\x00111\x00\x00" wide
        $m3 = "\x00\x00ETUN\x00\x00" wide
        $m4 = "\x00\x00ER\x00\x00" wide

    condition:
        any of them //todo: finetune this

}

rule LURK0 : Family LURK0 {
    
    meta:
        id = "5wxYPfd4LgwPzRd2UxBZiD"
        fingerprint = "v1_sha256_222cf0407106f36c99c1deafef466accd03cb9451f9274414cd7a4e259751347"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "rule for lurk0"
        category = "INFO"
        last_updated = "07-22-2014"

    condition:
        LURK0Header and SharedStrings

}

rule CCTV0 : Family CCTV0 {

    meta:
        id = "34ZkmdYum6Foz8aPRX5e3h"
        fingerprint = "v1_sha256_a1421827fbd63ae940604dc2b46b407bb18a6e4bb7d54c3e8454349b8317f8cc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "rule for cctv0"
        category = "INFO"
        last_updated = "07-22-2014"

    condition:
        CCTV0Header and SharedStrings

}
