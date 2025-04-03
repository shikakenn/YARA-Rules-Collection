rule Reign_1 {
    meta:
        id = "1lQiiakbjQ28sgaefDYogl"
        fingerprint = "v1_sha256_1d99ee65611060c090d4a1d44e86a2530340840b540ad783edba1304e93ae6ba"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        info = "REIGN"

    strings:
            $string_decode = {55 8b ec 5d 8b 45 08 0b c0 74 0c eb 05 fe 08 fe 08 40 80 38 00 75 f6}

    condition:
            $string_decode
}


rule Reign_Driver {
    meta:
        id = "4kPFzbZdBmcCsdrwgpZuZH"
        fingerprint = "v1_sha256_9efd4c42d8224a576c249fc11fee31aa8c33c46e0b46b4e89976d9cd5896266e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        info = "REIGN DRIVER COMPONENT (32-BIT)"

    strings:
        // 2C8B9D2885543D7ADE3CAE98225E263B
        // This is dead space at the end of the config block that will be constant between reconfigurations
        $config_block_padding = {c739f2c8ee70ebc9cf31fac0e678d3f1f709c2f8de40dbf9ff01caf0}

    condition:
        $config_block_padding
}


