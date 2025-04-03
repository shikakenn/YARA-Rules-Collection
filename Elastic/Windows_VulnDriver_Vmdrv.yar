rule Windows_VulnDriver_Vmdrv_7c674f8e {
    meta:
        id = "PxgJHZKNUkVZfUDPF8tup"
        fingerprint = "v1_sha256_87f29b861d5239c60e44541fe31ed90696068225b1b6d824dc9b06fcdb1597ae"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: vmdrv.sys, Version: 10.0.10011.16384"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Vmdrv"
        reference_sample = "32cccc4f249499061c0afa18f534c825d01034a1f6815f5506bf4c4ff55d1351"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 6D 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x00][\x00-\x40]|[\x00-\xff][\x00-\x3f])([\x00-\x1b][\x00-\x27]|[\x00-\xff][\x00-\x26])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x1a][\x00-\x27]|[\x00-\xff][\x00-\x26]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

