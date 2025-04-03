rule Windows_VulnDriver_ElRawDisk_f9fd1a80 {
    meta:
        id = "4lzm0HQsyOYhm8Qup4Yy4q"
        fingerprint = "v1_sha256_43f9f1f6ad6c1defe2f0d6dd0cd380bea1a8ead19bc0bf203bdfe4f83b9c284d"
        version = "1.0"
        date = "2022-10-07"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.ElRawDisk"
        reference_sample = "ed4f2b3db9a79535228af253959a0749b93291ad8b1058c7a41644b73035931b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\elrawdsk.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

