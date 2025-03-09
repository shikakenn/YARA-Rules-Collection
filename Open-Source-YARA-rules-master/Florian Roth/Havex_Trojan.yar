rule Havex_Trojan
    {
    meta:
        id = "5rhH9x8ZUGpOMzUDPHbfUM"
        fingerprint = "v1_sha256_c06e9911407f1deb94297bb343dd25563a0530650258346404f8ed5653550212"
        version = "1.0"
        date = "2014-06-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects the Havex RAT malware"
        category = "INFO"
        reference = "http://goo.gl/GO5mB1"
        hash = "7933809aecb1a9d2110a6fd8a18009f2d9c58b3c7dbda770251096d4fcc18849"

    strings:
        $magic = { 4d 5a }	
    
        $s1 = "Start finging of LAN hosts..." fullword wide
        $s2 = "Finding was fault. Unexpective error" fullword wide
        $s3 = "Hosts was't found." fullword wide
        $s4 = "%s[%s]!!!EXEPTION %i!!!" fullword wide
        $s5 = "%s  <%s> (Type=%i, Access=%i, ID='%s')" fullword wide
        $s6 = "Was found %i hosts in LAN:" fullword wide
        
        $x1 = "MB Connect Line GmbH" wide fullword
        $x2 = "mbCHECK" wide fullword
    condition:
        $magic at 0 and ( 2 of ($s*) or all of ($x*) )
}

