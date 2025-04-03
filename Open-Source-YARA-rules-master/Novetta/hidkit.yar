rule hidkit
{
    meta:
        id = "1oShXy6roO62ruyaQWAP5G"
        fingerprint = "v1_sha256_aed38550bc335560093239daa0dc1d09f2e39e3cb22ea2a31d47393ebc21d0ad"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Novetta"
        Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

    strings:
        $a = "---HIDE"
        $b = "hide---port = %d"

    condition:
        uint16(0)==0x5A4D and uint32(uint32(0x3c))==0x00004550 and $a and $b
}
