rule Exe_Cloaked_as_ThumbsDb
    {
    meta:
        id = "2EEn4OsuyMW7UAcDoKetSl"
        fingerprint = "v1_sha256_a85cd42f68cb2789d828a10ee6af077f002db7ed951d41be947ffd0741f3f989"
        version = "1.0"
        score = 50
        date = "2014-07-18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an executable cloaked as thumbs.db - Malware"
        category = "INFO"

    condition:
        uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}
