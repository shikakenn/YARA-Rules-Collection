private rule IMulerCode : IMuler Family 
{
    meta:
        id = "53f3E8E8kJjc94ghidWwoK"
        fingerprint = "v1_sha256_7be86b9fea2bddeb0e74c15d92367e758a8b359d9bd4ef62a7836826c6008073"
        version = "1.0"
        modified = "2014-06-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "IMuler code tricks"
        category = "INFO"

    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_tmpSpotlight = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 53 70 6F }
        $L4_TMPAAABBB = { C7 ?? ?? ?? ?? ?? 54 4D 50 41 C7 ?? ?? ?? ?? ?? 41 41 42 42 }
        $L4_FILEAGENTVer = { C7 ?? 46 49 4C 45 C7 ?? 04 41 47 45 4E }
        $L4_TMP0M34JDF8 = { C7 ?? ?? ?? ?? ?? 54 4D 50 30 C7 ?? ?? ?? ?? ?? 4D 33 34 4A }
        $L4_tmpmdworker = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 2E 6D 64 }
        
    condition:
        any of ($L4*)
}

private rule IMulerStrings : IMuler Family
{
    meta:
        id = "3230B50wij84Z92ZzmqoLV"
        fingerprint = "v1_sha256_f78aa4ce7e0af99ec5613a619d364a97b77410a65e0287f9c4a20f7639dd0fa6"
        version = "1.0"
        modified = "2014-06-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "IMuler Identifying Strings"
        category = "INFO"

    strings:
        $ = "/cgi-mac/"
        $ = "xnocz1"
        $ = "checkvir.plist"
        $ = "/Users/apple/Documents/mac back"
        $ = "iMuler2"
        $ = "/Users/imac/Desktop/macback/"
        $ = "xntaskz.gz"
        $ = "2wmsetstatus.cgi"
        $ = "launch-0rp.dat"
        $ = "2wmupload.cgi"
        $ = "xntmpz"
        $ = "2wmrecvdata.cgi"
        $ = "xnorz6"
        $ = "2wmdelfile.cgi"
        $ = "/LanchAgents/checkvir"
        $ = "0PERA:%s"
        $ = "/tmp/Spotlight"
        $ = "/tmp/launch-ICS000"
        
    condition:
        any of them
}


rule IMuler : Family
{
    meta:
        id = "6dNgj77dxGDhSyc19GvQKM"
        fingerprint = "v1_sha256_5b46a280d1da385fbcf04b5cb97bd843b8cf34eea621a23ab906c76eab7b8a26"
        version = "1.0"
        modified = "2014-06-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "IMuler"
        category = "INFO"

    condition:
        IMulerCode or IMulerStrings
}
