rule Linux_Hacktool_Cleanlog_c2907d77 {
    meta:
        id = "5Buk3DVY7uRj3tMAiybckP"
        fingerprint = "v1_sha256_39b72973bbcddf14604b8ea08339657cba317c23fd4d69d4aa0903b262397988"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "613ac236130ab1654f051d6f0661fa62414f3bef036ea4cc585b4b21a4bb9d2b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E5 48 83 EC 10 89 7D FC 83 7D FC 00 7E 11 8B 45 FC BE 09 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Cleanlog_3eb725d1 {
    meta:
        id = "BOoPuA3ZXcFZ651NnRHvA"
        fingerprint = "v1_sha256_a9530aca53d935f3e77a5f0fc332db16e3a2832be67c067e5a6d18e7ec00e39f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 E0 83 45 C0 01 EB 11 83 45 DC 01 EB 0B 83 45 D8 01 EB 05 83 45 }
    condition:
        all of them
}

rule Linux_Hacktool_Cleanlog_400b7595 {
    meta:
        id = "4gH5Yx6zS4Nx2f8cV3lmyv"
        fingerprint = "v1_sha256_e36acf708875efda88143124e11fef5b0e2f99d17b0c49344db969cf0d454db1"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 72 20 65 6E 74 72 79 20 28 64 65 66 61 75 6C 74 3A 20 31 73 74 20 }
    condition:
        all of them
}

