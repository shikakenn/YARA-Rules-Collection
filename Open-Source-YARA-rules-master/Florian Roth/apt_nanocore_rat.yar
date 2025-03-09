/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-04-22
    Identifier: Nanocore RAT
*/

rule Nanocore_RAT_Gen_1 {
    meta:
        id = "3qhN7XEWNLBCgCorgvpIrO"
        fingerprint = "v1_sha256_09fab3ef1b4ca9092fd69fb09c4ef759946fcb5b84161441bff797bb4009ed00"
        version = "1.0"
        score = 70
        date = "2016-04-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detetcs the Nanocore RAT and similar malware"
        category = "INFO"
        reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
        hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"

    strings:
        $x1 = "C:\\Users\\Logintech\\Dropbox\\Projects\\New folder\\Latest\\Benchmark\\Benchmark\\obj\\Release\\Benchmark.pdb" fullword ascii
        $x2 = "RunPE1" fullword ascii
        $x3 = "082B8C7D3F9105DC66A7E3267C9750CF43E9D325" fullword ascii
        $x4 = "$374e0775-e893-4e72-806c-a8d880a49ae7" fullword ascii
        $x5 = "Monitorinjection" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of them ) ) or ( 3 of them )
}

rule Nanocore_RAT_Gen_2 {
    meta:
        id = "3CxkJmRglJ9shrfQV6p3iU"
        fingerprint = "v1_sha256_23b3d149012fb8395b7daa2ecaf3ee66fdeac352ac94d632d76e52df2c6e8ea6"
        version = "1.0"
        score = 100
        date = "2016-04-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detetcs the Nanocore RAT"
        category = "INFO"
        reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
        hash1 = "755f49a4ffef5b1b62f4b5a5de279868c0c1766b528648febf76628f1fe39050"

    strings:
        $x1 = "NanoCore.ClientPluginHost" fullword ascii
        $x2 = "IClientNetworkHost" fullword ascii
        $x3 = "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or ( all of them )
}

rule Nanocore_RAT_Sample_1 {
    meta:
        id = "26wuk6zQv8WON3t2Z8xv9p"
        fingerprint = "v1_sha256_c74e5fe7e9d4dd7f032281b0e617f2355bc5844acf04a8ffbfd42165c7d9b8e4"
        version = "1.0"
        score = 75
        date = "2016-04-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detetcs a certain Nanocore RAT sample"
        category = "INFO"
        reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
        hash2 = "b7cfc7e9551b15319c068aae966f8a9ff563b522ed9b1b42d19c122778e018c8"

    strings:
        $x1 = "TbSiaEdJTf9m1uTnpjS.n9n9M7dZ7FH9JsBARgK" fullword wide
        $x2 = "1EF0D55861681D4D208EC3070B720C21D885CB35" fullword ascii
        $x3 = "popthatkitty.Resources.resources" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) ) ) or ( all of them )
}

rule Nanocore_RAT_Sample_2 {
    meta:
        id = "59bCtNZ3GybkhsgBq5KUTs"
        fingerprint = "v1_sha256_5110e5eb63e62d1e222582633daca26fd72f432a467f0a9926d34672ac4ed97b"
        version = "1.0"
        score = 75
        date = "2016-04-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detetcs a certain Nanocore RAT sample"
        category = "INFO"
        reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
        hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"

    strings:
        $s1 = "U4tSOtmpM" fullword ascii
        $s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" fullword wide
        $s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 40KB and all of ($s*)
}
