private rule RSharedStrings : Surtr Family {
    meta:
        id = "3bJhWCM2Ljf7kxgLcWTUK5"
        fingerprint = "v1_sha256_c8e8d21fc9e1952b4265a54c4305ac4ae0347f4b13df818263480241a2a06b22"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "identifiers for remote and gmremote"
        category = "INFO"
        last_updated = "07-21-2014"

    strings:
        $ = "nView_DiskLoydb" wide
        $ = "nView_KeyLoydb" wide
        $ = "nView_skins" wide
        $ = "UsbLoydb" wide
        $ = "%sBurn%s" wide
        $ = "soul" wide

    condition:
        any of them

}


private rule RemoteStrings : Remote Variant Surtr Family {
    meta:
        id = "IS3kjE0vZNwdxQfqgwHjT"
        fingerprint = "v1_sha256_3cfe5f1803733bbc9402d8d47f15009c9e1a1661c443182069097e98eec7038b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "indicators for remote.dll - surtr stage 2"
        category = "INFO"
        last_updated = "07-21-2014"

    strings:
        $ = "\x00Remote.dll\x00"
        $ = "\x00CGm_PlugBase::"
        $ = "\x00ServiceMain\x00_K_H_K_UH\x00"
        $ = "\x00_Remote_\x00" wide
    condition:
        any of them
}

private rule GmRemoteStrings : GmRemote Variant Family Surtr {
    meta:
        id = "40ESWHNKKkL3zRV4QF5sqp"
        fingerprint = "v1_sha256_4dfef2ffb4c0436afe2e80d3b7f4f65dacdb37830fad400b5dcaec8748fcc161"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "identifiers for gmremote: surtr stage 2"
        category = "INFO"
        last_updated = "07-21-2014"

    strings:
        $ = "\x00x86_GmRemote.dll\x00"
        $ = "\x00D:\\Project\\GTProject\\Public\\List\\ListManager.cpp\x00"
        $ = "\x00GmShutPoint\x00"
        $ = "\x00GmRecvPoint\x00"
        $ = "\x00GmInitPoint\x00"
        $ = "\x00GmVerPoint\x00"
        $ = "\x00GmNumPoint\x00"
        $ = "_Gt_Remote_" wide
        $ = "%sBurn\\workdll.tmp" wide
    
    condition:
        any of them

}

/*
 * Check if File has shared identifiers among Surtr Stage 2's
 * Then look for unique identifiers to each variant
*/

rule GmRemote : Family Surtr Variant GmRemote {
    meta:
        id = "668QRgzHYrOrpVz88M0J6f"
        fingerprint = "v1_sha256_5301be26a442cfbf90c360d111c9d15d643ec255e577c8970c9dbc4f962c4ad1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "identifier for gmremote"
        category = "INFO"
        last_updated = "07-25-2014"

    condition:
        RSharedStrings and GmRemoteStrings
}

rule Remote : Family Surtr Variant Remote {
    meta:
        id = "7lpaSQE7z9dIFP1iIuDHmu"
        fingerprint = "v1_sha256_d8049ccabcd4c69a6edd347a06f18dc8c4aabe2359be7522c6a3184972bd1834"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "identifier for remote"
        category = "INFO"
        last_updated = "07-25-2014"

    condition:
        RSharedStrings and RemoteStrings
}
