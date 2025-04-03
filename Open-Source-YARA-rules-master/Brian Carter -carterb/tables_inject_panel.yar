rule tables_inject

{

    meta:
        id = "Z6QjNSFeuaAnlsuhCsAYF"
        fingerprint = "v1_sha256_f892ebcf8f0ddbfa1d1b0f99bdc45f0a02987553350be4d8d9f00b7d9352ebd1"
        version = "1.0"
        modified = "August 14, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find zip archives of tables inject panel"
        category = "INFO"

    strings:
        $txt1 = "tinymce"
        $txt2 = "cunion.js"
        $txt3 = "tables.php"
        $txt4 = "sounds/1.mp3"
        $txt5 = "storage/db.sqlite"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
