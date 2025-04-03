rule Windows_VulnDriver_ThreatFire_cbe7ac92 {
    meta:
        id = "IJf4BHFgZZBszDXazBZbq"
        fingerprint = "v1_sha256_689e17c9fdfc9de10a2cf3d39306103712504ab46db35ac65ed0340c83af240d"
        version = "1.0"
        date = "2024-08-19"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.ThreatFire"
        reference_sample = "1c1a4ca2cbac9fe5954763a20aeb82da9b10d028824f42fff071503dcbe15856"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 66 00 53 00 79 00 73 00 4D 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $str1 = "ThreatFire" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and all of them
}

