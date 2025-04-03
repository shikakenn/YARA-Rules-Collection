rule dotfuscator : packer
{
    meta:
        id = "3BV6vLELslW0Aj70oQOqz2"
        fingerprint = "v1_sha256_c18a24fe408111e04fca411f9f7814d9477cd5e93822df894f8b91b3dc778bfd"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Dotfuscator"
        category = "INFO"
        filetype = "memory"

    strings:
        $a = "Obfuscated with Dotfuscator"

    condition:
        $a
}
