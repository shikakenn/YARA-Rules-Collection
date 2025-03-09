rule chinapic_zip

{

    meta:
        id = "5EmXaXNuRkTGPJ0dAp0jzP"
        fingerprint = "v1_sha256_65412d8a9a51e2151796a58a091f98c4e1014908d4964c576a958ebf9b30bf9a"
        version = "1.0"
        modified = "March 31, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find zip archives of pony panels that have china.jpg"
        category = "INFO"

    strings:
        $txt1 = "china.jpg"
        $txt2 = "config.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
