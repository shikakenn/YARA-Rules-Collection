rule Windows_VulnDriver_HpPortIo_b31e3473 {
    meta:
        id = "6w9VxfDzCO7gfkfbdD3oeU"
        fingerprint = "v1_sha256_e449b45f3cf2836254614bbdc957aa7093162fc1acd672edd931d5f240503963"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: HpPortIox64.sys, Version: 1.2.0.9"
        category = "INFO"
        threat_name = "Windows.VulnDriver.HpPortIo"
        reference_sample = "c5050a2017490fff7aa53c73755982b339ddb0fd7cef2cde32c81bc9834331c5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 70 00 50 00 6F 00 72 00 74 00 49 00 6F 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x02][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x09][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

