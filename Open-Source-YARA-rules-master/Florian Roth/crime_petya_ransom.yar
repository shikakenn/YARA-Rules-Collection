/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-03-24
    Identifier: Petya Ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

rule Petya_Ransomware {
    meta:
        id = "7OWVVC6wWoKEpf2FO4wxRh"
        fingerprint = "v1_sha256_9768b81cfc8ad8c5d251d07b8165f7fc5b01cd13e0c2cfee16e05473d22c1393"
        version = "1.0"
        date = "2016-03-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Petya Ransomware"
        category = "INFO"
        reference = "http://www.heise.de/newsticker/meldung/Erpressungs-Trojaner-Petya-riegelt-den-gesamten-Rechner-ab-3150917.html"
        hash = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"

    strings:
        $a1 = "<description>WinRAR SFX module</description>" fullword ascii

        $s1 = "BX-Proxy-Manual-Auth" fullword wide
        $s2 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
        $s3 = "X-HTTP-Attempts" fullword wide
        $s4 = "@CommandLineMode" fullword wide
        $s5 = "X-Retry-After" fullword wide
    condition:
    (
        uint16(0) == 0x5a4d and filesize < 500KB and 3 of them
    ) or (
        all of them
    ) and not filename matches /Google/
}
