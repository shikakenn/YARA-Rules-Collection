
rule Backdoor_Naikon_APT_Sample1 {
    meta:
        id = "5pm0DlnO4SJoMJTWXZRNPh"
        fingerprint = "v1_sha256_55257d8e146eca73433122ce6bf55b827344a8aa307e88fa9cc08e8d690423b8"
        version = "1.0"
        date = "2015-05-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects backdoors related to the Naikon APT"
        category = "INFO"
        reference = "https://goo.gl/7vHyvh"
        hash = "d5716c80cba8554eb79eecfb4aa3d99faf0435a1833ec5ef51f528146c758eba"
        hash = "f5ab8e49c0778fa208baad660fe4fa40fc8a114f5f71614afbd6dcc09625cb96"

    strings:
        $x0 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
        $x1 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
        $x2 = "greensky27.vicp.net" fullword ascii
        $x3 = "\\tempvxd.vxd.dll" fullword wide
        $x4 = "otna.vicp.net" fullword ascii
        $x5 = "smithking19.gicp.net" fullword ascii
        
        $s1 = "User-Agent: webclient" fullword ascii
        $s2 = "\\User.ini" fullword ascii
        $s3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" ascii
        $s4 = "\\UserProfile.dll" fullword wide
        $s5 = "Connection:Keep-Alive: %d" fullword ascii
        $s6 = "Referer: http://%s:%d/" fullword ascii
        $s7 = "%s %s %s %d %d %d " fullword ascii
        $s8 = "%s--%s" fullword wide
        $s9 = "Run File Success!" fullword wide
        $s10 = "DRIVE_REMOTE" fullword wide
        $s11 = "ProxyEnable" fullword wide
        $s12 = "\\cmd.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and
        (
            1 of ($x*) or 7 of ($s*)
        )
}

