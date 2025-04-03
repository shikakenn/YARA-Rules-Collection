rule Linux_Trojan_Getshell_98d002bf {
    meta:
        id = "4lj81tkjT43IMdgk5G2HaZ"
        fingerprint = "v1_sha256_358575f55910b060bde94bbc55daa9650a43cf1470b77d1842ddcaa8b299700a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Getshell"
        reference_sample = "97b7650ab083f7ba23417e6d5d9c1d133b9158e2c10427d1f1e50dfe6c0e7541"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B2 6A B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_213d4d69 {
    meta:
        id = "6ahsaraaOwM8enOtENgZ4g"
        fingerprint = "v1_sha256_2075def88b31ac32e44c270ab20273c8b91f37e25a837c0353f76bcf431cdcb3"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "05fc4dcce9e9e1e627ebf051a190bd1f73bc83d876c78c6b3d86fc97b0dfd8e8"
        threat_name = "Linux.Trojan.Getshell"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EC 01 00 00 00 EB 3C 8B 45 EC 48 98 48 C1 E0 03 48 03 45 D0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_3cf5480b {
    meta:
        id = "6ARBCclxl0dfvIJcJo52cl"
        fingerprint = "v1_sha256_87b0db74e81d4f236b11f51a72fba2e4263c988402292b2182d19293858c6126"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "0e41c0d6286fb7cd3288892286548eaebf67c16f1a50a69924f39127eb73ff38"
        threat_name = "Linux.Trojan.Getshell"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B2 24 B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_8a79b859 {
    meta:
        id = "7c9YdvHzO6wVtKa3Y4AWOl"
        fingerprint = "v1_sha256_2aa3914ec4cc04e5daa2da1460410b4f0e5e7a37c5a2eae5a02ff5f55382f1fe"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "1154ba394176730e51c7c7094ff3274e9f68aaa2ed323040a94e1c6f7fb976a2"
        threat_name = "Linux.Trojan.Getshell"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0A 00 89 E1 6A 1C 51 56 89 E1 43 6A 66 58 CD 80 B0 66 B3 04 }
    condition:
        all of them
}

