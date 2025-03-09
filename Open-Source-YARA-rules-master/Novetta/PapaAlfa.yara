rule PapaAlfa
{
    meta:
        id = "4tHt6TtGY7AcHdFsCTqLpd"
        fingerprint = "v1_sha256_bfba8d147022b7e2d9f3d2d95a85b63415d8d0c8ad5412c06664553625457d88"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $ = "pmsconfig.msi" wide
        $ = "pmslog.msi" wide
        $ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d"
        $ = "CreatP2P Thread" wide
        $ = "GreatP2P Thread" wide
    condition:
        3 of them
}
