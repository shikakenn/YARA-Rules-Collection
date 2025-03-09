/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-05-25
    Identifier: Kaspersky Report on threats involving CVE-2015-2545
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mal_Dropper_httpEXE_from_CAB {
    meta:
        id = "5fV99k3KWLmFX7zwIZUzPL"
        fingerprint = "v1_sha256_d114a3ab348bba49a78852b87b712908bc974bf35a2b841099a232e761cad8f2"
        version = "1.0"
        score = 60
        date = "2016-05-25"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a dropper from a CAB file mentioned in the article"
        category = "INFO"
        reference = "https://goo.gl/13Wgy1"
        hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"

    strings:
        $s1 = "029.Hdl" fullword ascii
        $s2 = "http.exe" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) )
}

rule Mal_http_EXE {
    meta:
        id = "1yuBz4vUYRhgpbgcJ3bIgl"
        fingerprint = "v1_sha256_f9cde6ced7bfa506839001f976284a4df3539ce4f1887067966d5c24b0cd5fd7"
        version = "1.0"
        score = 80
        date = "2016-05-25"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects trojan from APT report named http.exe"
        category = "INFO"
        reference = "https://goo.gl/13Wgy1"
        hash1 = "ad191d1d18841f0c5e48a5a1c9072709e2dd6359a6f6d427e0de59cfcd1d9666"

    strings:
        $x1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" fullword ascii
        $x2 = "%ALLUSERSPROFILE%\\Accessories\\wordpade.exe" fullword ascii
        $x3 = "\\dumps.dat" fullword ascii
        $x4 = "\\wordpade.exe" fullword ascii
        $x5 = "\\%s|%s|4|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
        $x6 = "\\%s|%s|5|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
        $x7 = "cKaNBh9fnmXgJcSBxx5nFS+8s7abcQ==" fullword ascii
        $x8 = "cKaNBhFLn1nXMcCR0RlbMQ==" fullword ascii /* base64: pKY1[1 */

        $s1 = "SELECT * FROM moz_logins;" fullword ascii
        $s2 = "makescr.dat" fullword ascii
        $s3 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
        $s4 = "?moz-proxy://" fullword ascii
        $s5 = "[%s-%s] Title: %s" fullword ascii
        $s6 = "Cforeign key mismatch - \"%w\" referencing \"%w\"" fullword ascii
        $s7 = "Windows 95 SR2" fullword ascii
        $s8 = "\\|%s|0|0|" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 2 of ($s*) ) ) or ( 3 of ($x*) )
}

rule Mal_PotPlayer_DLL {
    meta:
        id = "6Akkr8pAgl8vZE70lnAUOL"
        fingerprint = "v1_sha256_fa1ae63900ce64f7795c7297c2c6c0497c131ff5a3270642dfb486b182ea285e"
        version = "1.0"
        score = 70
        date = "2016-05-25"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a malicious PotPlayer.dll"
        category = "INFO"
        reference = "https://goo.gl/13Wgy1"
        hash1 = "705409bc11fb45fa3c4e2fa9dd35af7d4613e52a713d9c6ea6bc4baff49aa74a"

    strings:
        $x1 = "C:\\Users\\john\\Desktop\\PotPlayer\\Release\\PotPlayer.pdb" fullword ascii

        $s3 = "PotPlayer.dll" fullword ascii
        $s4 = "\\update.dat" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and $x1 or all of ($s*)
}
