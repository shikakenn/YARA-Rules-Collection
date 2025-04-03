rule Bublik : Downloader
{
    meta:
        id = "3BLi5MNdv5kryL3lMAS4Yt"
        fingerprint = "v1_sha256_ea70244a4a4f5497f6ee3898c29920e69acdbbf6f3fc6bc89cdb96297f6cd609"
        version = "1.0"
        date = "29/09/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Bublik Trojan Downloader"
        category = "INFO"

    strings:
        $signature1={63 6F 6E 73 6F 6C 61 73}
        $signature2={63 6C 55 6E 00 69 6E 66 6F 2E 69 6E 69}
        
    condition:
        $signature1 and $signature2
}
