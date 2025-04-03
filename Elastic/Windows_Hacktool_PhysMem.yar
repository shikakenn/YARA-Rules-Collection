rule Windows_Hacktool_PhysMem_cc0978df {
    meta:
        id = "2IciuBweHpRHReiygcnBkA"
        fingerprint = "v1_sha256_e2fabf5889dbdc98dc6942be4fb0de4351d64a06bab945993b2a2c4afe89984e"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: physmem.sys"
        category = "INFO"
        threat_name = "Windows.Hacktool.PhysMem"
        reference_sample = "c299063e3eae8ddc15839767e83b9808fd43418dc5a1af7e4f44b97ba53fbd3d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 68 00 79 00 73 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_Hacktool_PhysMem_b3fa382b {
    meta:
        id = "31uy0Mw0M02IDEY7RfIQKK"
        fingerprint = "v1_sha256_36a60b78de15a52721ad4830b37daffc33d7689e8b180fe148876da00562273a"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.PhysMem"
        reference_sample = "88df37ede18bea511f1782c1a6c4915690b29591cf2c1bf5f52201fbbb4fa2b9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\Phymemx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

