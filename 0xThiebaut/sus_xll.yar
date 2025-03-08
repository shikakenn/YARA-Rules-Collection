import "pe"

rule sus_xll_xlAutoOpen_empty: TESTING SUSPICIOUS TA0003 T1137 T1137_006 {
    meta:
        id = "IKlkRzFlrc1iw7JdK41Ul"
        fingerprint = "v1_sha256_d25fc45d7bbf6824b8454a0e8f1664caa6d035588a22983d9ace3c682dadc37d"
        version = "1.1"
        date = "2023-05-13"
        modified = "2023-05-13"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects an Excel XLL file exporting an empty xlAutoOpen function, often indicative of hidden logic inside DllMain"
        category = "INFO"
        mitre_att = "T1137.006"
        reference = "https://learn.microsoft.com/en-us/office/client-developer/excel/creating-xlls#turning-dlls-into-xlls-add-in-manager-interface-functions"
        reference = "https://learn.microsoft.com/en-us/office/client-developer/excel/xlautoopen"
        first_imported = "2023-05-13"

    condition:
        pe.exports("xlAutoOpen")
        and (
            uint8(pe.export_details[pe.exports_index("xlAutoOpen")].offset) == 0xC3  // ret
            or (
                uint16(pe.export_details[pe.exports_index("xlAutoOpen")].offset) == 0xC033     // xor eax eax
                and uint8(pe.export_details[pe.exports_index("xlAutoOpen")].offset+2) == 0xC3  // ret
            )
        )
}

rule sus_xll_xlAutoClose_empty: TESTING SUSPICIOUS TA0003 T1137 T1137_006 {
    meta:
        id = "6of2wrJksv1WZcHOthgatn"
        fingerprint = "v1_sha256_3b0d558844b4748a4e23e7efe058ec0eb6c2792d802201ad7d1a6d60e95dcb72"
        version = "1.0"
        date = "2023-05-13"
        modified = "2023-05-13"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects an Excel XLL file exporting the optional xlAutoClose as an empty function"
        category = "INFO"
        mitre_att = "T1137.006"
        reference = "https://learn.microsoft.com/en-us/office/client-developer/excel/xlautoclose"
        first_imported = "2023-05-13"

    condition:
        pe.exports("xlAutoClose")
        and (
            uint8(pe.export_details[pe.exports_index("xlAutoClose")].offset) == 0xC3  // ret
            or (
                uint16(pe.export_details[pe.exports_index("xlAutoClose")].offset) == 0xC033     // xor eax eax
                and uint8(pe.export_details[pe.exports_index("xlAutoClose")].offset+2) == 0xC3  // ret
            )
        )
}
