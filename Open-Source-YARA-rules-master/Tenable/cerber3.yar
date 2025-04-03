rule ammyy_cerber3 {
    meta:
        id = "59j98xh15HwzC4KEf2baz"
        fingerprint = "v1_sha256_4c9203ead39a6ed98b317fc3c1e57da0190303340a5022b2313d27c03448edce"
        version = "1.0"
        date = "09/28/2016"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "AA_V3.5.EXE"
        author = "Rich Walchuck"
        description = "Rule to detect Ammyy Admin / Cerber 3.0 Ransomware"
        category = "INFO"
        md5 = "54d07ec77e3daaf32b2ba400f34dd370"
        sha1 = "3a99641ba00047e1be23dfae4fcf6242b8b8eb10"
        sha256 = "99b84137b5b8b3c522414e332526785e506ed2dbe557eafc40a7bcf47b623d88"

    strings:
        $s0 = "mailto:support@ammy.com" fullword ascii
        $s1 = "@$&%04\\Uninstall.exe" fullword ascii
        $s2 = "@$&%05\\encrypted.exe" fullword ascii
        $s3 = "http://www.ammy.com/" fullword ascii
        $s4 = "@$&%05\\AA_v3.exe" fullword ascii
        $s5 = "ammy 1.00 - Smart Install Maker" fullword ascii
        $s6 = "ammy 1.00 Installation" fullword wide
        $s7 = "Ammy" fullword wide
    condition:
        all of them
}
