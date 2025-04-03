rule Windows_VulnDriver_Biostar_d6cc23af {
    meta:
        id = "7a3ehCCILClpy3PsEki8d5"
        fingerprint = "v1_sha256_6a1f5de3a0daf446ceb812a9f5749410a3a7752dce44e935adc288c95816f59d"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: BS_HWMIO64_W10.sys, Version: 10.0.1806.2200"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 48 00 57 00 4D 00 49 00 4F 00 36 00 34 00 5F 00 57 00 31 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x98][\x00-\x08]|[\x00-\xff][\x00-\x07])([\x00-\x0e][\x00-\x07]|[\x00-\xff][\x00-\x06])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0d][\x00-\x07]|[\x00-\xff][\x00-\x06]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_68682378 {
    meta:
        id = "7NEWZHnXJkilTNtexPd136"
        fingerprint = "v1_sha256_8510de6fc33bde153f3bd4d1bb8b0d98ce69aae479d242c6043ac8c712dbb888"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: BS_I2cIo.sys, Version: 1.1.0.0"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 49 00 32 00 63 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_684a5123 {
    meta:
        id = "1s0sIfQXeLVdNX7IdpMwWW"
        fingerprint = "v1_sha256_7c0c7e14f9b5085a87e5dbe27feb8e49bdb4d2fdcfbcbc643999d7969d118240"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: BS_RCIO64.sys, Version: 10.0.0.1"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 52 00 43 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_e0b6cf55 {
    meta:
        id = "2vHwSYv1UsvZqG6ugxRgTO"
        fingerprint = "v1_sha256_dccbf6fa46de1a8bc6438578b651055e2d02d15bd04461be74059e6fde40fca3"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "73327429c505d8c5fd690a8ec019ed4fd5a726b607cabe71509111c7bfe9fc7e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\BS_RCIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

