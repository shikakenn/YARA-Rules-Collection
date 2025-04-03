rule Hancitor
{
    meta:
        id = "2JUVnWqQpbD1im3VIG8lCf"
        fingerprint = "v1_sha256_84003542a2f587b5fbd43731c4240759806f8ee46df2bd96aae4a3c09d97e41c"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "threathive"
        description = "Hancitor Payload"
        category = "INFO"
        cape_type = "Hancitor Payload"

    strings:
       $fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
       $fmt_string2 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
       $ipfy = "http://api.ipify.org"
       $user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
    condition:
        uint16(0) == 0x5A4D and all of them
}
