rule BadRabbit
{
    meta:
        id = "2ITryKdPApdy9WxYktuOxV"
        fingerprint = "v1_sha256_309e14ab4ea2f919358631f9d8b2aaff1f51e7708b6114e4e6bf4a9d9a5fc86c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "BadRabbit Payload"
        category = "INFO"
        cape_type = "BadRabbit Payload"

    strings:
        $a1 = "caforssztxqzf2nm.onion" wide
        $a2 = "schtasks /Create /SC once /TN drogon /RU SYSTEM" wide
        $a3 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
