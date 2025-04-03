rule Wiper_Ukr_Feb_2022 {
    meta:
        id = "1HFEXgaFOYMVCiX7yqE6rv"
        fingerprint = "v1_sha256_fa96b88c42bdd4ba437f090d781b38c5c7f9fcb690aeff4161f24aedb1870587"
        version = "1.0"
        date = "2022-02-23"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "cadosecurity.com"
        description = "Detects Wiper seen in Ukraine 23rd Feb 2022"
        category = "INFO"
        report = "HTTPS://GITHUB.COM/CADO-SECURITY/WIPER_FEB_2022"
        hash = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
        license = "Apache License 2.0"
        ref1 = "https://twitter.com/threatintel/status/1496578746014437376"
        ref2 = "https://twitter.com/ESETresearch/status/1496581903205511181"

    strings:
        $ = "Hermetica Digital Ltd" wide ascii
        $ = "DRV_XP_X64" wide ascii
        $ = "Windows\\System32\\winevt\\Logs" wide ascii
        $ = "EPMNTDRV\\%u" wide ascii
    condition:
      uint16(0) == 0x5A4D and all of them
}
