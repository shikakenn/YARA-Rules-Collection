rule Grozlex : Stealer
{
    meta:
        id = "Ate95u0kXj7swVYgRWzD5"
        fingerprint = "v1_sha256_a1b1ef88c693ae52bcfd7ce7a7cf51eed7ba7b2e6f0c69a6ac94099dff79919d"
        version = "1.0"
        date = "20/08/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Grozlex Stealer - Possible HCStealer"
        category = "INFO"

    strings:
        $signature={4C 00 6F 00 67 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 62 00 79 00 20 00 69 00 43 00 6F 00 7A 00 65 00 6E}
    
    condition:
        $signature
}
