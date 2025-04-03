rule venom
{
    meta:
        id = "3WPiTCU3gZxlsqaIHhE317"
        fingerprint = "v1_sha256_59cd3965584f886ef105652f0367e0ae02c59ccf2cef7da75ce0350ea3cddc98"
        version = "1.0"
        date = "2017-01-31"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "HTTPS://SECURITY.WEB.CERN.CH/SECURITY/VENOM.SHTML"
        author = "Rich Walchuck"
        description = "Venom Linux Rootkit"
        category = "INFO"
        hash = "a5f4fc353794658a5ca2471686980569"

    strings:
        $string0 = "%%VENOM%OK%OK%%"
        $string1 = "%%VENOM%WIN%WN%%"
        $string2 = "%%VENOM%CTRL%MODE%%"
        $string3 = "%%VENOM%AUTHENTICATE%%"
        $string4 = "venom by mouzone"
        $string5 = "justCANTbeSTOPPED"

    condition:
        any of them
}
