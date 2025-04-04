rule Windows_Wiper_HermeticWiper_7206a969 {
    meta:
        id = "3hWzjzh3bjeFpEhmhQm4tw"
        fingerprint = "v1_sha256_84c61b8223a6ebf1ccfa4fdccee3c9091abca4553e55ac6c2492cff5503b4774"
        version = "1.0"
        date = "2022-02-24"
        modified = "2022-02-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper"
        threat_name = "Windows.Wiper.HermeticWiper"
        reference_sample = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

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

