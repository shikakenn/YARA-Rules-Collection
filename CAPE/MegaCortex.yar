rule MegaCortex
{
    meta:
        id = "3rOCR3WTmgSnQYvtjnswu3"
        fingerprint = "v1_sha256_5de1d8241260070241c91b97f18feb2a90069e3b158e863e2d9f568799c244e6"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "MegaCortex Payload"
        category = "INFO"
        cape_type = "MegaCortex Payload"

    strings:
        $str1 = ".megac0rtx" ascii wide
        $str2 = "vssadmin delete shadows /all" ascii
        $sha256 = {98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9}
    condition:
        uint16(0) == 0x5A4D and all of them
}
