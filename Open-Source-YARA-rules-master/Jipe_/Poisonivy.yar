rule poisonivy : rat
{
    meta:
        id = "6oqD2cEblhWXnkOum8AUaN"
        fingerprint = "v1_sha256_4d2a865697afc0ac3734b49c1cc40579d9422e5fe0ad177308611f82df4110b2"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Poison Ivy"
        category = "INFO"
        filetype = "memory"
        ref1 = "https://code.google.com/p/volatility/source/browse/trunk/contrib/plugins/malware/poisonivy.py"

    strings:
        $a = { 53 74 75 62 50 61 74 68 ?? 53 4F 46 54 57 41 52 45 5C 43 6C 61 73 73 65 73 5C 68 74 74 70 5C 73 68 65 6C 6C 5C 6F 70 65 6E 5C 63 6F 6D 6D 61 6E 64 [22] 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 41 63 74 69 76 65 20 53 65 74 75 70 5C 49 6E 73 74 61 6C 6C 65 64 20 43 6F 6D 70 6F 6E 65 6E 74 73 5C } 
        
    condition:
        $a
}
