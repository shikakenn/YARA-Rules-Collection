
/* LENOVO Superfish -------------------------------------------------------- */

rule VisualDiscovery_Lonovo_Superfish_SSL_Hijack {
    meta:
        id = "7Ohuknjp86pmbnVNz6Hr1x"
        fingerprint = "v1_sha256_ed2f03a2bb38610e84854b287628b940f03e814dde85986096b2431b722e622a"
        version = "1.0"
        date = "2015/02/19"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth / improved by kbandla"
        description = "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"
        category = "INFO"
        reference = "https://twitter.com/4nc4p/status/568325493558272000"
        hash1 = "99af9cfc7ab47f847103b5497b746407dc566963"
        hash2 = "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46"
        hash3 = "f12edf2598d8f0732009c5cd1df5d2c559455a0b"
        hash4 = "343af97d47582c8150d63cbced601113b14fcca6"

    strings:
        $mz = { 4d 5a }
        //$s1 = "VisualDiscovery.exe" fullword wide
        $s2 = "Invalid key length used to initialize BlowFish." fullword ascii
        $s3 = "GetPCProxyHandler" fullword ascii
        $s4 = "StartPCProxy" fullword ascii
        $s5 = "SetPCProxyHandler" fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 2MB and all of ($s*)
}
