rule office_document_vba
{
    meta:
        id = "2Hh5ftweNCFUhCl7edsRz5"
        fingerprint = "v1_sha256_f51ad520618a62df71792ba88778e05f5260d08688eee6557ac0e38f38685a71"
        version = "1.0"
        date = "2013-12-17"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Office document with embedded VBA"
        category = "INFO"
        reference = "N/A"

    strings:
        $officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
        $zipmagic = "PK"

        $97str1 = "_VBA_PROJECT_CUR" wide
        $97str2 = "VBAProject"
        $97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }

        $xmlstr1 = "vbaProject.bin"
        $xmlstr2 = "vbaData.xml"

    condition:
        ($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
