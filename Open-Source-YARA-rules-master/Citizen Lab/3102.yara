private rule APT3102Code : APT3102 Family 
{
    meta:
        id = "5CgVOFUye27S6VSezLeZWo"
        fingerprint = "v1_sha256_221b4fd05f63ea9af939bcbcfe43ccce8dbf81f3d8b44c980fac05b7b08f159a"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "3102 code features"
        category = "INFO"

    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }
  
    condition:
        any of them
}

private rule APT3102Strings : APT3102 Family
{
    meta:
        id = "4yOfrcaUB0LjaEzwgMDijC"
        fingerprint = "v1_sha256_14ccfd764296c23657d96e2a1373915ea696a47ef530082ae9dfa7ee55c148c1"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "3102 Identifying Strings"
        category = "INFO"

    strings:
        $ = "rundll32_exec.dll\x00Update"
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"
        
    condition:
       any of them
}

rule APT3102 : Family
{
    meta:
        id = "Hn4LGi51wVoqporUi3ISf"
        fingerprint = "v1_sha256_a2df4cabd3a528d6d8813e9c68eab28ed7a117fb66bc186f6f0d9883746bc856"
        version = "1.0"
        modified = "2014-06-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "3102"
        category = "INFO"

    condition:
        APT3102Code or APT3102Strings
}
