rule Windows_Hacktool_CpuLocker_73b41444 {
    meta:
        id = "3k5SmxrE7ETcJKtReQe4XF"
        fingerprint = "v1_sha256_8fb33744326781c51bb6bd18d0574602256b813b62ec8344d5338e6442bb2de0"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.CpuLocker"
        reference_sample = "dbfc90fa2c5dc57899cc75ccb9dc7b102cb4556509cdfecde75b36f602d7da66"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\CPULocker.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

