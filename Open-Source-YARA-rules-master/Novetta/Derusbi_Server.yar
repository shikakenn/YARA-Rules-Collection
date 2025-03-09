rule Derusbi_Server
{
    meta:
        id = "2Mzs3MugR9xqOZhC5RKts5"
        fingerprint = "v1_sha256_cf1234eaa0967d3feaee94c8200808232e95ca23653a5feafac3c8cc4d16815f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Novetta"
        Reference = "http://www.novetta.com/wp-content/uploads/2014/11/Derusbi.pdf"

    strings:
        $uuid = "{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" wide ascii
        $infectionID1 = "-%s-%03d"
        $infectionID2 = "-%03d"
        $other = "ZwLoadDriver"

    condition:
        $uuid or ($infectionID1 and $infectionID2 and $other)
}
