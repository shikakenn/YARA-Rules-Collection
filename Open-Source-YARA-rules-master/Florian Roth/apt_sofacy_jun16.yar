/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-06-14
    Identifier: Sofacy June 2016
*/

/* Rule Set ----------------------------------------------------------------- */

rule Sofacy_Jun16_Sample1 {
    meta:
        id = "6HoVwE9L7beeNmFsiGb99Y"
        fingerprint = "v1_sha256_761cec3d04e6b5273cfb450000023ed10ea73d17648c0af7660f4ef2b37fc31c"
        version = "1.0"
        score = 85
        date = "2016-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
        category = "INFO"
        reference = "http://goo.gl/mzAa97"
        hash1 = "be1cfa10fcf2668ae01b98579b345ebe87dab77b6b1581c368d1aba9fd2f10a0"

    strings:
        $s1 = "clconfg.dll" fullword ascii
        $s2 = "ASijnoKGszdpodPPiaoaghj8127391" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($s*) ) ) or ( all of them )
}

rule Sofacy_Jun16_Sample2 {
    meta:
        id = "2Mqhri54R0h3fcwa04kYh3"
        fingerprint = "v1_sha256_a1f334996527556334c34d0308da6165e9d2a3d7eb8b2ecc322b574dea4d4844"
        version = "1.0"
        score = 85
        date = "2016-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
        category = "INFO"
        reference = "http://goo.gl/mzAa97"
        hash1 = "57d230ddaf92e2d0504e5bb12abf52062114fb8980c5ecc413116b1d6ffedf1b"
        hash2 = "69940a20ab9abb31a03fcefe6de92a16ed474bbdff3288498851afc12a834261"
        hash3 = "aeeab3272a2ed2157ebf67f74c00fafc787a2b9bbaa17a03be1e23d4cb273632"

    strings:
        $x1 = "DGMNOEP" fullword ascii
        $x2 = "/%s%s%s/?%s=" fullword ascii

        $s1 = "Control Panel\\Dehttps=https://%snetwork.proxy.ht2" fullword ascii
        $s2 = "http=http://%s:%Control Panel\\Denetwork.proxy.ht&ol1mS9" fullword ascii
        $s3 = "svchost.dll" fullword wide
        $s4 = "clconfig.dll" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 100KB and ( all of ($x*) ) ) or ( 3 of them )
}

rule Sofacy_Jun16_Sample3 {
    meta:
        id = "4fPmyoyVcOI41HXQ3xlTAg"
        fingerprint = "v1_sha256_bdc6fcc30ebd7a966391747e4156a6d94dc9187e8b8898de4c441540ec4e637e"
        version = "1.0"
        score = 85
        date = "2016-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
        category = "INFO"
        reference = "http://goo.gl/mzAa97"
        hash1 = "c2551c4e6521ac72982cb952503a2e6f016356e02ee31dea36c713141d4f3785"

    strings:
        $s1 = "ASLIiasiuqpssuqkl713h" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and $s1
}
