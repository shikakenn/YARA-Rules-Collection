
rule ce_enfal_cmstar_debug_msg {
    meta:
        id = "ymTM0EZNKYhWxZdbFBqNL"
        fingerprint = "v1_sha256_31251b7ce33eb561aeb7405514df83dc1e00fdf184e3deeaa48505407d9567a0"
        version = "1.0"
        date = "5/10/2015"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "rfalcone"
        description = "Detects the static debug strings within CMSTAR"
        category = "INFO"
        reference = "http://goo.gl/JucrP9"
        hash = "9b9cc7e2a2481b0472721e6b87f1eba4faf2d419d1e2c115a91ab7e7e6fc7f7c"

    strings:
        $d1 = "EEE\x0d\x0a" fullword
        $d2 = "TKE\x0d\x0a" fullword
        $d3 = "VPE\x0d\x0a" fullword
        $d4 = "VPS\x0d\x0a" fullword
        $d5 = "WFSE\x0d\x0a" fullword
        $d6 = "WFSS\x0d\x0a" fullword
        $d7 = "CM**\x0d\x0a" fullword
    condition:
        uint16(0) == 0x5a4d and all of ($d*)
}
