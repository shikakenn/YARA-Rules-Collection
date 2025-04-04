rule weird_zip_high_compression_ratio: RELEASED WEIRD T1204 T1204_002 {
    meta:
        id = "5eINBToFy4WWGjhO9nxpiP"
        fingerprint = "v1_sha256_cc005b0d89bcaef28b60bb5bf18b0e67543aaab88582aa154e676ab1918cb44d"
        version = "1"
        date = "2023-04-06"
        modified = "2023-04-06"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects single-entry ZIP files with a suspiciously high compression ratio (>100:1) and decompressed size above the 500MB AV limit"
        category = "INFO"
        mitre_att = "T1204.002"
        reference = "https://twitter.com/Cryptolaemus1/status/1633099154623803394"
        hash = "4d9a6dfca804989d40eeca9bb2d90ef33f3980eb07ca89bbba06d0ef4b37634b"
        first_imported = "2023-04-06"

    condition:
        // Find ZIP files...
        uint32(filesize-22) == 0x06054b50 
        // with only one entry on disk...
        and uint16(filesize-14) == 1
        // and only one entry in directory.
        and uint16(filesize-12) == 1
        // Where the directory...
        and uint32(uint32(filesize-6)) == 0x02014b50
        // has an uncompressed size larger than the AV limit...
        and uint32(uint32(filesize-6)+24) >= 500MB
        // while the compressed ration is high (>100:1 compression ratio)
        and uint32(uint32(filesize-6)+20) * 100 < uint32(uint32(filesize-6)+24)
}
