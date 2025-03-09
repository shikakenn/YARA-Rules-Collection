rule ggupdate_windows {
    meta:
        id = "XyOPjvE7ZfThdIctFFDZx"
        fingerprint = "v1_sha256_53bcd7b651eb71995715c94180c83c5e9f331ec414f3fc4508b3c4f8de0d0011"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "ggupdate.exe keylogger (Windows)"
        category = "INFO"

    strings:
        // 9706A7D1479EB0B5E60535A952E63F1A
        // these strings are located in the packer or are unprotected
        $s1 = "Les Blues"
        $s2 = "lesblues.exe"
        $s3 = "Boodled8"
        $s4 = "Misexplain6"
        $s5 = "lesblues"
        $s6 = "Sniffs5"
        $s7 = "Oneiromancy"
        $s8 = "Lophtcrack" ascii wide

    condition:
        IsPeFile and 3 of them
}


rule ggupdate_linux {
    meta:
        id = "3dhCmxvANqDHZqWBIJvlmA"
        fingerprint = "v1_sha256_5891fa72fa0de0a06a4d55551b29d7cd426f7d107c9f2c4f40feb9ca002169a1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "ggupdate keylogger (Linux)"
        category = "INFO"

    strings:
        // 4611DAA8CF018B897A76FBAB51665C62
        $s1 = "%s.Identifier"
        $s2 = "0:%llu:%s;"
        $s3 = "%s%.2d-%.2d-%.4d"
        $s4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

    condition:
        IsElfFile and 3 of them
}


