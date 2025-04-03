// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_HARDPULSE 
{ 
    meta:
        id = "2rakUCS7rZgO6foyn251tp"
        fingerprint = "v1_sha256_37fc40fd998d3294edb05707170bc2deec524fc6451bff212901f9ac3e34bb35"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        date_created = "2021-04-16"
        md5 = "980cba9e82faf194edb6f3cc20dc73ff"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"

    strings: 
        $r1 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}unless[\x09\x20]{0,32}\(open\(\$\w{1,64},[\x09\x20]{0,32}\$\w{1,64}\)\)\s{0,128}\{\s{1,128}goto[\x09\x20]{1,32}\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}return[\x09\x20]{1,32}0[\x09\x20]{0,32}\x3b\s{0,128}\}/ 
        $r2 = /open[\x09\x20]{0,32}\(\*\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>/ 
        $r3 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}print[\x09\x20]{0,32}[\x22\x27]Content-type/ 
        $s1 = "CGI::request_method()" 
        $s2 = "CGI::param(" 
        $s3 = "syswrite(" 
        $s4 = "print $_" 
    condition: 
        all of them 
} 
