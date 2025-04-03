/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-09-01
    Identifier: Rocket Kitten Keylogger
*/

rule RocketKitten_Keylogger {
    meta:
        id = "50dcuU8EAVlqO2yQfqEtEx"
        fingerprint = "v1_sha256_c8523a50075c6ee9675d37d870da55d9e6193bbc770f6b916e700ab9aad438cc"
        version = "1.0"
        date = "2015-09-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Keylogger used in Rocket Kitten APT"
        category = "INFO"
        reference = "https://goo.gl/SjQhlp"
        super_rule = 1
        hash1 = "1c9e519dca0468a87322bebe2a06741136de7969a4eb3efda0ab8db83f0807b4"
        hash2 = "495a15f9f30d6f6096a97c2bd8cc5edd4d78569b8d541b1d5a64169f8109bc5b"

    strings:
        $x1 = "\\Release\\CWoolger.pdb" ascii
        $x2 = "WoolenLoger\\obj\\x86\\Release" ascii
        $x3 = "D:\\Yaser Logers\\"
        
        $z1 = "woolger" fullword wide

        $s1 = "oShellLink.TargetPath = \"" fullword ascii
        $s2 = "wscript.exe " fullword ascii
        $s3 = "strSTUP = WshShell.SpecialFolders(\"Startup\")" fullword ascii
        $s4 = "[CapsLock]" fullword ascii
    condition:
        /* File detection */
        (uint16(0) == 0x5a4d and filesize < 200KB and (1 of ($x*) or ($z1 and 2 of ($s*)))) or
        /* Memory detection */
        ($z1 and all of ($s*)) 
}
