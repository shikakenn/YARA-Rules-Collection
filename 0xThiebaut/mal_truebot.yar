rule mal_truebot: TESTING MALWARE TA0002 T1027 T1204_002 {
    meta:
        id = "4g0ZwriUKaUkgyXHmpiJSJ"
        fingerprint = "v1_sha256_4a930daa082bf4da10ff3e2dfd84dd6d9148766ecd71dbc886dc69fc533b3327"
        version = "1.0"
        date = "2023-05-25"
        modified = "2023-05-25"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THEDFIRREPORT.COM"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects strings commonly related to TrueBot functionality"
        category = "MALWARE"
        malware = "TRUEBOT"
        mitre_att = "T1204.002"
        reference = "https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/"
        hash = "717beedcd2431785a0f59d194e47970e9544fbf398d462a305f6ad9a1b1100cb"
        first_imported = "2023-05-25"

    strings:
        $c2_params_1        = "n=%s&o=%s&a=%d&u=%s&p=%s&d=%s" fullword
        $c2_params_2        = "n=%s&l=%s"   fullword
        $c2_id              = "%08x-%08x"   fullword
        $c2_status          = "Not Found"   fullword
        $c2_method          = "POST "       fullword
        $c2_proto           = "HTTP/1.0"    fullword
        $c2_header_host     = "Host: "      fullword
        $c2_header_ct       = "Content-type: application/x-www-form-urlencoded" fullword
        $other_workgroup    = "WORKGROUP"           fullword
        $other_unknown      = "UNKW"                fullword
        $load_perms         = "SeDebugPrivilege"    fullword
        $load_library       = "user32"              fullword wide
        $load_import        = "RtlCreateUserThread" fullword
        $cmd_del            = "/c del" fullword wide

    condition:
        13 of them
}
