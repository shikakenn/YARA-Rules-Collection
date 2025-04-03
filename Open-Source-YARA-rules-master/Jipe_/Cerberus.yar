rule Cerberus : rat
{
    meta:
        id = "3hzXRQB9uH2STBmJ0nLRPH"
        fingerprint = "v1_sha256_5c27422771a1d51ccf74af95d085a4d2f09f6644b7b3e90b243fd31bf1417e22"
        version = "1.0"
        date = "2013-01-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Cerberus"
        category = "INFO"
        filetype = "memory"

    strings:
        $checkin = "Ypmw1Syv023QZD"
        $clientpong = "wZ2pla"
        $serverping = "wBmpf3Pb7RJe"
        $generic = "cerberus" nocase

    condition:
        any of them
}
