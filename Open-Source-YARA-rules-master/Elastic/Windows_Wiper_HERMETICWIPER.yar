rule Windows_Wiper_HERMETICWIPER {
    meta:
        id = "Sub6vazW3Lb91tE2QH5fV"
        fingerprint = "v1_sha256_84c61b8223a6ebf1ccfa4fdccee3c9091abca4553e55ac6c2492cff5503b4774"
        version = "1.0"
        date = "2022-02-24"
        modified = "2022-02-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Detects HERMETICWIPER used to target Ukrainian organization"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper"
        Author = "Elastic Security"
        os = "Windows"
        arch = "x86"
        category_type = "Wiper"
        family = "HERMETICWIPER"
        threat_name = "Windows.Wiper.HERMETICWIPER"
        reference_sample = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"

    strings:
        $a1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
        $a2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
        $a3 = "tdrv.pdb" ascii fullword
        $a4 = "%s%.2s" wide fullword
        $a5 = "ccessdri" ascii fullword
        $a6 = "Hermetica Digital"
    condition:
        all of them
}
