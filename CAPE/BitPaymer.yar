rule BitPaymer
{
    meta:
        id = "5LZXMhx0pEMuJevGtnlFWZ"
        fingerprint = "v1_sha256_6ae0dc9a36da13e483d8d653276b06f59ecc15c95c754c268dcc91b181677c4c"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "BitPaymer Payload"
        category = "INFO"
        cape_type = "BitPaymer Payload"

    strings:
        $decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
        $antidefender = "TouchMeNot" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
