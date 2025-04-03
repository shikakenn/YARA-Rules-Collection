rule Windows_VulnDriver_Rtkio_13b3c88b {
    meta:
        id = "4LO94eDCpWdr1MzGI3Ru4o"
        fingerprint = "v1_sha256_1e37650292884e28dcc51c42bc1b1d1e8efc13b0727f7865ff1dc7b8e1a72380"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: rtkio.sys"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_VulnDriver_Rtkio_d595781e {
    meta:
        id = "3KqgcNG0jt7M40RmH9IAzz"
        fingerprint = "v1_sha256_289eb17025d989cc74e109b1c03378e9760817a84f1a759153ff6ff6b6401e6d"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: rtkio64.sys"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "4ed2d2c1b00e87b926fb58b4ea43d2db35e5912975f4400aa7bd9f8c239d08b7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_VulnDriver_Rtkio_b09af431 {
    meta:
        id = "5g289ChcrNmqXrVNURPeIE"
        fingerprint = "v1_sha256_916a6e63dc4c7ee0bfdf4a455ee467a1d03c1042db60806511aa7cbf3b096190"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: rtkiow8x64.sys"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "b205835b818d8a50903cf76936fcf8160060762725bd74a523320cfbd091c038"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 38 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_VulnDriver_Rtkio_5693e967 {
    meta:
        id = "6v12Y0DYsEVZnb7Co8h7wx"
        fingerprint = "v1_sha256_4cbc7a52de7f610cdb12bf40a9099bcfae818dcb5e4119a8c34499433aeebd7e"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: rtkiow10x64.sys"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "ab8f2217e59319b88080e052782e559a706fa4fb7b8b708f709ff3617124da89"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 31 00 30 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

