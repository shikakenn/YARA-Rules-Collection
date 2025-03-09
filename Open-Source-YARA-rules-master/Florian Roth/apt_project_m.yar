/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-03-26
    Identifier: ProjectM
*/

/* Rule Set ----------------------------------------------------------------- */

rule ProjectM_DarkComet_1 {
    meta:
        id = "6X2y7mOSSTzmbhamruKjzN"
        fingerprint = "v1_sha256_fbb67d6b2ce8c2e0b593300ec8de6bc173cb7e317c769b16c2b1fcacddbc86a2"
        version = "1.0"
        date = "2016-03-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects ProjectM Malware - file cc488690ce442e9f98bac651218f4075ca36c355d8cd83f7a9f5230970d24157"
        category = "INFO"
        reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
        hash = "cc488690ce442e9f98bac651218f4075ca36c355d8cd83f7a9f5230970d24157"

    strings:
        $x1 = "DarkO\\_2" fullword ascii

        $a1 = "AVICAP32.DLL" fullword ascii
        $a2 = "IDispatch4" fullword ascii
        $a3 = "FLOOD/" fullword ascii
        $a4 = "T<-/HTTP://" fullword ascii
        $a5 = "infoes" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them ) or ( all of them )
}

rule ProjectM_CrimsonDownloader {
    meta:
        id = "3kW7d5cUGu8DiLZwaARLJA"
        fingerprint = "v1_sha256_3c9a4f5aca4c9fc26d371027a32e349a456ef25d6b403a66b9afb1ee19dd4d00"
        version = "1.0"
        date = "2016-03-26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects ProjectM Malware - file dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"
        category = "INFO"
        reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
        hash = "dc8bd60695070152c94cbeb5f61eca6e4309b8966f1aa9fdc2dd0ab754ad3e4c"

    strings:
        $x1 = "E:\\Projects\\m_project\\main\\mj shoaib"

        $s1 = "\\obj\\x86\\Debug\\secure_scan.pdb" ascii
        $s2 = "secure_scan.exe" fullword wide
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|mswall" fullword wide
        $s4 = "secure_scan|mswall" fullword wide
        $s5 = "[Microsoft-Security-Essentials]" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and $x1 ) or ( all of them )
}
