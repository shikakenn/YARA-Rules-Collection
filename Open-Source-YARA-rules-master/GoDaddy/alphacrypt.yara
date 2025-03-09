rule alphacrypt {
    meta:
        id = "1jsBjtYQf1vCdMX2K1JIoN"
        fingerprint = "v1_sha256_ab2edd13cbf12c2021bdd6ed85793973a0bfe361f07c8290c0dcf2500a4065da"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        info = "ALPHACRYPT RANSOMWARE"

    strings:
        // configuration data is stored as a 32-bit value  at offset 0x58
        // the first and last bytes are signatures and must be 0xFE, and
        // the middle word is read as an integer
        $config_data = { 54 68 69 73 20 70 72 6F 67 72 FE ?? ?? FE 61 6E 
            6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65 }                          

    condition:
        $config_data
}

