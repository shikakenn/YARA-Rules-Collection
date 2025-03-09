
rule PoisonIvy_Generic_3 {
    meta:
        id = "4Fx6hHjQrL2W1Ii634M1ZD"
        fingerprint = "v1_sha256_8116b07c00218a0e9784447f322455ff24ae754770b85db760b1c397e10e5695"
        version = "1.0"
        date = "2015-05-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "PoisonIvy RAT Generic Rule"
        category = "INFO"
        hash = "e1cbdf740785f97c93a0a7a01ef2614be792afcd"

    strings:
        $k1 = "Tiger324{" fullword ascii
        
        $s2 = "WININET.dll" fullword ascii
        $s3 = "mscoree.dll" fullword wide
        $s4 = "WS2_32.dll" fullword
        $s5 = "Explorer.exe" fullword wide
        $s6 = "USER32.DLL"
        $s7 = "CONOUT$"
        $s8 = "login.asp"
        
        $h1 = "HTTP/1.0"
        $h2 = "POST"
        $h3 = "login.asp"
        $h4 = "check.asp"
        $h5 = "result.asp"
        $h6 = "upload.asp"
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and
            ( 
                $k1 or all of ($s*) or all of ($h*)
            )
}
