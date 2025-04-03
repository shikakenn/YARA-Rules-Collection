rule Windows_Hacktool_LeiGod_89397ebf {
    meta:
        id = "1p0OhPzPSWWxGkZKYO0WOm"
        fingerprint = "v1_sha256_e887c34c624a182a3c57a55abe02784c4350d3956bcfd9f7918f08a464819e63"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.LeiGod"
        reference_sample = "ae5cc99f3c61c86c7624b064fd188262e0160645c1676d231516bf4e716a22d3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\Device\\CtrlLeiGod" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_LeiGod_3f5c98c4 {
    meta:
        id = "1A51G00ZDqLWJpi6WGsrCP"
        fingerprint = "v1_sha256_7570bf1a69df6b493bde41c1de27969e36a3fcb59be574ee2e24e3a61347a146"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.LeiGod"
        reference_sample = "0c42fe45ffa9a9c36c87a7f01510a077da6340ffd86bf8509f02c6939da133c5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\LgDCatcher.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

