// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_PULSEJUMP_1
{
    meta:
        id = "7JsU9DKysZdweFbkjQsQQZ"
        fingerprint = "v1_sha256_c9aa2b9ef8aff14c20ed6597b1a71eafc3e3c181aabf9a3a68df18945207ff86"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        date_created = "2021-04-16"
        md5 = "91ee23ee24e100ba4a943bb4c15adb4c"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"

    strings:
        $s1 = "open("
        $s2 = ">>/tmp/"
        $s3 = "syswrite("
        $s4 = /\}[\x09\x20]{0,32}elsif[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27](Radius|Samba|AD)[\x22\x27][\x09\x20]{0,32}\)\s{0,128}\{\s{0,128}@\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}&/
    condition:
        all of them
}
