//will match both exe and dll components
private rule NetTravExports : NetTraveler Family {

    meta:
        id = "7TKjJ5jLzijVflNXlkHb54"
        fingerprint = "v1_sha256_a7d4ea6bdd3726c4560e33f6fee5dcc77ec6aad454da7ce329ca6ed0374dedc1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Export names for dll component"
        category = "INFO"
        last_updated = "2014-05-20"

    strings:
        //dll component exports
        $ = "?InjectDll@@YAHPAUHWND__@@K@Z"
        $ = "?UnmapDll@@YAHXZ"
        $ = "?g_bSubclassed@@3HA"
        
    condition:
        any of them
}

private rule NetTravStrings : NetTraveler Family {


    meta:
        id = "16WBm4RRc7CBQKfSK0PQtp"
        fingerprint = "v1_sha256_0c682a060f90d14aebea4b0239b0343e44687c34b1a53d5b9c1b62be445828b5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Identifiers for NetTraveler DLL"
        category = "INFO"
        last_updated = "2014-05-20"

    strings:
        //network strings
        $ = "?action=updated&hostid="
        $ = "travlerbackinfo"
        $ = "?action=getcmd&hostid="
        $ = "%s?action=gotcmd&hostid="
        $ = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="

        //debugging strings
        $ = "\x00Method1 Fail!!!!!\x00"
        $ = "\x00Method3 Fail!!!!!\x00"
        $ = "\x00method currect:\x00"
        $ = /\x00\x00[\w\-]+ is Running!\x00\x00/
        $ = "\x00OtherTwo\x00"

    condition:
        any of them

}

private rule NetpassStrings : NetPass Variant {

    meta:
        id = "5x6j1jmpUjU14BCeBgtfzh"
        fingerprint = "v1_sha256_d18a118d7a46555d55e3d3e7ba5616bbbf15d43d1ba7d7ccf41351c0872287b8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Identifiers for netpass variant"
        category = "INFO"
        last_updated = "2014-05-29"

        strings:
        $exif1 = "Device Protect ApplicatioN" wide
        $exif2 = "beep.sys" wide //embedded exe name
        $exif3 = "BEEP Driver" wide //embedded exe description
        
        $string1 = "\x00NetPass Update\x00"
        $string2 = "\x00%s:DOWNLOAD\x00"
        $string3 = "\x00%s:UPDATE\x00"
        $string4 = "\x00%s:uNINSTALL\x00"

        condition:
                all of ($exif*) or any of ($string*)

}	


rule NetTraveler : Family {
    meta:
        id = "4rWDT7PPcyFnYdZLlqwJN5"
        fingerprint = "v1_sha256_679c68116b49d34b8556fe821c9f6e9a12668bf35c6b6212e256b205f6a2aea6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Nettravelr"
        category = "INFO"
        last_updated = "2014-07-08"

    condition:
        NetTravExports or NetTravStrings or NetpassStrings

}

rule NetPass : Variant {
    meta:
        id = "6kl7ELBZ8wFwMa333kQoDH"
        fingerprint = "v1_sha256_fab94d00047f13db5345868c1d83d2c58e6e241dcbdcf77c07bf4e594fee70ce"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "netpass variant"
        category = "INFO"
        last_updated = "2014-07-08"

    condition:
        NetpassStrings
}
