private rule NSFreeCode : NSFree Family 
{
    meta:
        id = "2UzrOmF8hEg1v0qnZHL4Z8"
        fingerprint = "v1_sha256_b323c469b68bbd1088be66753b99dd0067e3572361f1c8aeba407b2f37310b22"
        version = "1.0"
        modified = "2014-06-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "NSFree code features"
        category = "INFO"

    strings:
        // push vars then look for MZ
        $ = { 53 56 57 66 81 38 4D 5A }
        // nops then look for PE\0\0
        $ = { 90 90 90 90 81 3F 50 45 00 00 }
    
    condition:
        all of them
}

private rule NSFreeStrings : NSFree Family
{
    meta:
        id = "1DHdHwlnkXHMjZZuNT4VqE"
        fingerprint = "v1_sha256_55b208fbaa96e4f3a215b0e355e51d06b99f6970c189feb962e7d295cf7bd15d"
        version = "1.0"
        modified = "2014-06-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "NSFree Identifying Strings"
        category = "INFO"

    strings:
        $ = "\\MicNS\\" nocase
        $ = "NSFreeDll" wide ascii
        // xor 0x58 dos stub
        $ = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }
        
    condition:
       any of them
}

rule NSFree : Family
{
    meta:
        id = "1G6KbjrLKGvwtitFjVGhrb"
        fingerprint = "v1_sha256_0fa7d06146c5e154b6eeb47514d1116a90f291f67032eaf0e9a15334b3a764f3"
        version = "1.0"
        modified = "2014-06-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "NSFree"
        category = "INFO"

    condition:
        NSFreeCode or NSFreeStrings
}
