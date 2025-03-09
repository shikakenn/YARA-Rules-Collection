rule doc
{
    meta:
        id = "Dk3kz8PJvY3ZcyVAXCPvc"
        fingerprint = "v1_sha256_5df9d5ea29faa61faf512cf695863f23b6bdc4867b60d633cd96fd596fe6e71d"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Word 2003 file format detection"
        category = "INFO"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }
        $str1 = "Microsoft Office Word"
        $str2 = "MSWordDoc"
        $str3 = "Word.Document.8"
    condition:
       $header at 0 and any of ($str*) 
}

rule ppt
{
    meta:
        id = "4CRrthNfMkYHvsj77zdwkB"
        fingerprint = "v1_sha256_b727fc1ca60ebaba9925b12a1d07eb90e185dca01f9fe912eac1ee714ee033e8"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "PowerPoint 2003 file format detection"
        category = "INFO"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }
        $str = "Microsoft Office PowerPoint"
    condition:
       $header at 0 and $str
}

rule xls
{
    meta:
        id = "5SqDvQfHleDMYjZTtzCVmV"
        fingerprint = "v1_sha256_303093ea8cdb9173dd89b203865aeabbc2c5c741171303ac75a1141a0a0b32f0"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Excel 2003 file format detection"
        category = "INFO"

    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }
        $str1 = "Microsoft Excel"
        $str2 = "Excel.Sheet.8"
    condition:
       $header at 0 and any of ($str*) 
}

rule docx
{
    meta:
        id = "6B9PSOO37vb7XkzIdPlB3L"
        fingerprint = "v1_sha256_5ac3469d6425282724af2789ee9ab403d62263309268bcb68189d034fb6551ce"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Word 2007 file format detection"
        category = "INFO"

    strings:
        $header = { 50 4B 03 04 }
        $str = "document.xml"
    condition:
       $header at 0 and $str
}

rule pptx
{
    meta:
        id = "4Bejy0u5OUWSZIU5Jp0saA"
        fingerprint = "v1_sha256_c2360d4fdecdea02a2cdd1e28a629c635f50c8e8013a218d7e557e586e0d5e09"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "PowerPoint 2007 file format detection"
        category = "INFO"

    strings:
        $header = { 50 4B 03 04 }
        $str = "presentation.xml"
    condition:
       $header at 0 and $str
}

rule xlsx
{
    meta:
        id = "3YgcdihppTY862MZ93Bljl"
        fingerprint = "v1_sha256_3af4fd4076954b79ea8876238876af4ed87b1058f6dcc8b97428f503b51ae858"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Excel 2007 file format detection"
        category = "INFO"

    strings:
        $header = { 50 4B 03 04 }
        $str = "workbook.xml"
    condition:
       $header at 0 and $str
}

rule xlsb
{
    meta:
        id = "J6XugVhyTAkoSx9i2LJ8t"
        fingerprint = "v1_sha256_6f53ac596b03da7a3724ebd75297374369301bdf952f8d78745b6ed8db045973"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Excel Binary Workbook file format detection"
        category = "INFO"

    strings:
        $header = { 50 4B 03 04 }
        $str = "workbook.bin"
    condition:
       $header at 0 and $str
}

rule rtf
{
    meta:
        id = "39HUtX9OVgSp4xZNuQLQUL"
        fingerprint = "v1_sha256_1bd8399644512813246a2a9499259c166edc52efd1c4030a996c0bea2739305c"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Word RTF file format detection"
        category = "INFO"

    strings:
        $header = "{\\rt"	
    condition:
       $header at 0
}

rule word_xml
{
    meta:
        id = "7Lrfb36bl0htUfD54ERkFV"
        fingerprint = "v1_sha256_756464791a50aea4b157ab3814667cfe33336e51e3ce95c0f9f85e5da095c0d6"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Word XML file format detection"
        category = "INFO"

    strings:
        $header = "<?xml"
        $str = "<?mso-application progid=\"Word.Document\"?>"
    condition:
       $header at 0 and $str
}

rule ppt_xml
{
    meta:
        id = "4cNh3aNsxesvApT170bq5l"
        fingerprint = "v1_sha256_3765a8dad25e3db0b5cc38a86cef571e66b8fcc0e8b51b200b8db32d706f5888"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "PowerPoint XML file format detection"
        category = "INFO"

    strings:
        $header = "<?xml"
        $str = "<?mso-application progid=\"PowerPoint.Show\"?>"
    condition:
       $header at 0 and $str
}

rule excel_xml
{
    meta:
        id = "2KdhROIZSfrU3RPacmoK9l"
        fingerprint = "v1_sha256_8ca624df15cc4c2757fc5d165d0f86b65403f6a30aec91248a2e50f731ec2e4f"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Excel XML file format detection"
        category = "INFO"

    strings:
        $header = "<?xml"
        $str = "<?mso-application progid=\"Excel.Sheet\"?>"
    condition:
       $header at 0 and $str
}

rule mhtml
{
    meta:
        id = "39h1n78O9IjAXDhP1ZfA7V"
        fingerprint = "v1_sha256_e842eb1d030ec7539bc5c944b62266b67284d2effedbef5f97a67e9bc02706a7"
        version = "1.0"
        date = "2016/04/26"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Word/Excel MHTML file format detection"
        category = "INFO"

    strings:
        $str1 = "MIME-Version:"
        $str2 = "Content-Location:"
        $email_str1 = "From:"
        $email_str2 = "Subject:"
    condition:
        all of ($str*) and not any of ($email_str*)
}
