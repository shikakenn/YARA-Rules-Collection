// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_2 
{ 
    meta:
        id = "3lU5ycySdfAMff7DXUtm35"
        fingerprint = "v1_sha256_4ade993176c918ec23e99fc585e9ab14d9f9e93a7eca00f2c3b0ebbd13d6ec5b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        date_created = "2021-04-16"
        md5 = "4a2a7cbc1c8855199a27a7a7b51d0117"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"

    strings: 
        $s1 = "open(*fd," 
        $s2 = "syswrite(*fd," 
        $s3 = "close(*fd);" 
        $s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/[\w.]{1,128}[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$\w{1,128} ?[\x22\x27],[\x09\x20]{0,32}5000\)/ 
    condition: 
        all of them 
} 
