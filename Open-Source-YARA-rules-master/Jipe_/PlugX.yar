rule plugX : rat
{
    meta:
        id = "4b6Bl04ZQHftHNS9agMp3e"
        fingerprint = "v1_sha256_b2e981571cf6e2893bd51a82d3233baca76d21b6591d6e012aded278324ff3df"
        version = "1.0"
        date = "2014-05-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "PlugX RAT"
        category = "INFO"
        filetype = "memory"
        ref1 = "https://github.com/mattulm/IR-things/blob/master/volplugs/plugx.py"

    strings:
        $v1a = { 47 55 4C 50 00 00 00 00 }
        $v1b = "/update?id=%8.8x" 
        $v1algoa = { BB 33 33 33 33 2B } 
        $v1algob = { BB 44 44 44 44 2B } 
        $v2a = "Proxy-Auth:" 
        $v2b = { 68 A0 02 00 00 } 
        $v2k = { C1 8F 3A 71 } 
        
    condition: 
        $v1a at 0 or $v1b or (($v2a or $v2b) and (($v1algoa and $v1algob) or $v2k))
}
