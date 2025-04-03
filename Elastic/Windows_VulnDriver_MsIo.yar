rule Windows_VulnDriver_MsIo_aa20a3c6 {
    meta:
        id = "4ZtLkIoyXyZbJ6ouodXEqR"
        fingerprint = "v1_sha256_3b383934dc91536f69e2c6cb2cf2054c5f8a08766ecf1d1804c57f3a2c39c1c2"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.MsIo"
        reference_sample = "2270a8144dabaf159c2888519b11b61e5e13acdaa997820c09798137bded3dd6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\MsIo32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_MsIo_ce0bda23 {
    meta:
        id = "52iyysGC2inM6BqBZgkyj0"
        fingerprint = "v1_sha256_f7fbe0255a006cce42aff61b294512c11e1cceaf11d5c1b6f75b96fb3b155895"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.MsIo"
        reference_sample = "43ba8d96d5e8e54cab59d82d495eeca730eeb16e4743ed134cdd495c51a4fc89"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\MsIo64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

