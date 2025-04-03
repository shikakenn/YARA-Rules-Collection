rule Conti
{
    meta:
        id = "2U1oh9CBlkTSZYbqsiWESR"
        fingerprint = "v1_sha256_c9842f93d012d0189b9c6f10ad558b37ae66226bbb619ad677f6906ccaf0e848"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "kevoreilly"
        description = "Conti Ransomware"
        category = "INFO"
        cape_type = "Conti Payload"

    strings:
        $crypto1 = {8A 07 8D 7F 01 0F B6 C0 B9 ?? 00 00 00 2B C8 6B C1 ?? 99 F7 FE 8D [2] 99 F7 FE 88 ?? FF 83 EB 01 75 DD}
        $website1 = "https://contirecovery.info" ascii wide
        $website2 = "https://contirecovery.best" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
