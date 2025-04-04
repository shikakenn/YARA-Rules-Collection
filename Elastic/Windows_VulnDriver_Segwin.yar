rule Windows_VulnDriver_Segwin_04a3962e {
    meta:
        id = "49gwl7mOLwOV9kd3iGxIhS"
        fingerprint = "v1_sha256_1e9ba5fc78f2b4eeee56314c9e8cf3071817d726b44cb8510f8d7069e85ab7bf"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: segwindrvx64.sys, Version: 100.0.7.2"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Segwin"
        reference_sample = "65329dad28e92f4bcc64de15c552b6ef424494028b18875b7dba840053bc0cdd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 67 00 77 00 69 00 6E 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x64][\x00-\x00])([\x00-\x02][\x00-\x00])([\x00-\x07][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x63][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x64][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x06][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

