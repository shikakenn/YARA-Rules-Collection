rule mal_electron_js_backdoor: RELEASED MALWARE BACKDOOR TA0002 T1059 T1059_007 {
    meta:
        id = "2SpYwBSdt1oei2hZGj1Jca"
        fingerprint = "v1_sha256_751d8a1f486a5144a33cc872f6dde5f3daad56b99713a864ad8808026017793b"
        version = "1.1"
        date = "2021-11-04"
        modified = "2023-02-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects suspicious JavaScript statements linked to an Electron backdoor deployed by FalconForce"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1574"
        reference = "https://github.com/electron/electron/commit/57d088517ceef0d6c7bd6dde6fd740813c3cf943#diff-913b4eb0955fc49f1792447dc4dc58049e89d29b8d6366ba986fcb51b48963a4"
        hash = "a148e00ef1a18e5d687f04dda6512526e9b8b2053e78d5461540a3939cf4f87c"
        first_imported = "2023-02-23"

    strings:
        $require            = "require"        fullword
        $require_fs         = "fs"             fullword
        $require_path       = "path"           fullword
        $require_electron   = "electron"       fullword
        $require_net        = "net"            fullword
        $require_crypto     = "crypto"         fullword
        $require_os         = "os"             fullword
        $require_process    = "process"        fullword
        $crypto_random      = "randomBytes"    fullword
        $crypto_iv          = "createCipheriv" fullword
        $func_eval          = "eval"           fullword

    condition:
        9 of them and $func_eval and any of ($crypto_*) and #require >= 4 and #require_electron >= 2 and filesize <= 150KB
}
