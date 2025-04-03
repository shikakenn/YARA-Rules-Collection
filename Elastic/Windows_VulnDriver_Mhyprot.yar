rule Windows_VulnDriver_Mhyprot_26214176 {
    meta:
        id = "5EXc417oXYiUZ8rTdfCfW2"
        fingerprint = "v1_sha256_61d1713c689b9d663f2d3360d07735b07ca10365b5ce424b2df726bd6cc434d3"
        version = "1.0"
        date = "2022-08-25"
        modified = "2022-08-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Subject: miHoYo Co.,Ltd., Version: 1.0.0.0"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Mhyprot"
        reference_sample = "509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $subject_name = { 06 03 55 04 03 [2] 6D 69 48 6F 59 6F 20 43 6F 2E 2C 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
        $str1 = "\\Device\\mhyprot2" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}

