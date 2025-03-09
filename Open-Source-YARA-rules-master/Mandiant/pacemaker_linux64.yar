// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux_PACEMAKER 
{ 
    meta:
        id = "2fXE2OwgEoEO23rgNZmp0t"
        fingerprint = "v1_sha256_cf83024cbbd500a301ac3c859b680cd79acabc232ea6f42c23fe9f8918a8d914"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        date_created = "2021-04-16"
        md5 = "d7881c4de4d57828f7e1cab15687274b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"

    strings: 
        $s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00" 
        $s2 = "\x00/proc/%d/mem\x00" 
        $s3 = "\x00/proc/%s/maps\x00" 
        $s4 = "\x00/proc/%s/cmdline\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}
