rule MacOS_Backdoor_Keyboardrecord_832f7bac {
    meta:
        id = "4NPlFrvN1yrUvCyYW7ePIH"
        fingerprint = "v1_sha256_5719681d50134edacb5341034314c33ed27e9325de0ae26b2a01d350429c533b"
        version = "1.0"
        date = "2021-11-11"
        modified = "2022-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Backdoor.Keyboardrecord"
        reference_sample = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $s1 = "com.ccc.keyboardrecord"
        $s2 = "com.ccc.write_queue"
        $s3 = "ps -p %s > /dev/null"
        $s4 = "useage %s path useragentpid"
        $s5 = "keyboardRecorderStartPKc"
    condition:
        3 of them
}

