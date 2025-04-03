rule MacOS_Infostealer_MdQueryTCC_142313cb {
    meta:
        id = "7enUqitTfVPa4VtySUaUFH"
        fingerprint = "v1_sha256_e00015867ad0a0c440a49364945fe828d50675ecfd2039028653d97c77cff323"
        version = "1.0"
        date = "2023-04-11"
        modified = "2024-08-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Infostealer.MdQueryTCC"
        reference_sample = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $string1 = { 6B 4D 44 49 74 65 6D 44 69 73 70 6C 61 79 4E 61 6D 65 20 ( 3D | 3D ) 20 2A 54 43 43 2E 64 62 }
    condition:
        any of them
}

