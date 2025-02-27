rule Windows_VulnDriver_Ryzen_7df5a747 {
    meta:
        id = "32O7FAKlJDO8xUHyFoL6DB"
        fingerprint = "v1_sha256_192b51f0bbd2cab4c1d3da6f82fbee7129a53abaa6e8769d3681821112017824"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Name: AMDRyzenMasterDriver.sys, Version: 1.5.0.0"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x05][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x04][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Ryzen_9b01c718 {
    meta:
        id = "4hQ8sjzLmMPnvJw569DfsU"
        fingerprint = "v1_sha256_5734f6a249656f22a2a363b42ae77b5e6b7673bc96bad34b04b1be7f2b584b08"
        version = "1.0"
        date = "2023-01-22"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Name: AMDRyzenMasterDriver.sys, Version: <= 1.7.0.0"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "bb82d8c29127955d58dff58978605a9daa718425c74c4bce5ae3e53712909148"
        severity = 49
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x07][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x06][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version
}

