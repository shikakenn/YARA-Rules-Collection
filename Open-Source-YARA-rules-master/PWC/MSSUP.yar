 rule MSSUP : AST

{

    meta:
        id = "5V7KlCDCy4VhDDZfv28vPA"
        fingerprint = "v1_sha256_992c8fdec153843411d36eada318a2f21277983d06bd92f5323f0ede16a1b443"
        version = "1.0"
        date = "2014-09-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        author = "PwC Cyber Threat Operations"
        description = "NA"
        category = "INFO"
        reference = "http://pwc.blogs.com/cyber_security_updates/2014/09/malware-microevolution.html"
        hash = "8083ee212588a05d72561eebe83c57bb"

 strings:

       $debug1="d:\\Programming\\CSharp\\BlackBerry\\BlackBerry\\obj\\Debug\\MSSUP.pdb" nocase

       $debug2="D:\\Programming\\CSharp\\BlackBerry\\UploadDownload\\bin\\x86\\Debug\\UploadDownload.pdb" nocase

       $debug3="Unexpected error has been occurred in {0}, the process must restart for some reason, if it's first time you see this message restart the {0}, if problem was standing contacts the support team ."

       $fileheader1="MSSUP" ascii wide

       $fileheader2="1.0.0.0" ascii wide

       $fileheader3="2014" ascii wide

       $configload1="sqlite3.dll"

       $configload2="URLExtractRegex"

       $configload3="HTTPHeaderName"

       $configload4="HTTPHeaderType"

       $configload5="MsupPath"

 

condition:

       (all of ($fileheader*) or 3 of ($configload*)) and filesize < 200KB or any of ($debug*)

}

