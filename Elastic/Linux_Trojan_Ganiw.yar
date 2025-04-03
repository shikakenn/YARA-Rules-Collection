rule Linux_Trojan_Ganiw_99349371 {
    meta:
        id = "1uDFkaiRhyl5XU5KpALGoK"
        fingerprint = "v1_sha256_26160e855c63fc0b73e415de2fe058f2005df1ec5544d21865d022c5474df30c"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ganiw"
        reference_sample = "e8dbb246fdd1a50226a36c407ac90eb44b0cf5e92bf0b92c89218f474f9c2afb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 66 89 43 02 8B 5D FC C9 C3 55 89 E5 53 83 EC 04 8B 45 14 8B }
    condition:
        all of them
}

rule Linux_Trojan_Ganiw_b9f045aa {
    meta:
        id = "5HXTE8U9QNlxYKTYUZir14"
        fingerprint = "v1_sha256_2565101b261bee22ddecf6898ff0ac8a114d09c822d8db26ba3e3571ebe06b12"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ganiw"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E5 57 8B 55 0C 85 D2 74 21 FC 31 C0 8B 7D 08 AB AB AB AB AB AB }
    condition:
        all of them
}

