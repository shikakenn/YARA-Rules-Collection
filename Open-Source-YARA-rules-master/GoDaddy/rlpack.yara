rule rlpack {
    meta:
        id = "5rGARd4nutMkQIre1aCdNJ"
        fingerprint = "v1_sha256_abe29136585f04815c1b719c9c4ceb38d063faa97ac002df697aa35e128c3f03"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "RLPack packed file"
        category = "INFO"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $text1 = ".packed\x00"
        $text2 = ".RLPack\x00"

    condition:
        $mz at 0 and $text1 in (0..1024) and $text2 in (0..1024)
}

