rule Linux_Trojan_Iroffer_53692410 {
    meta:
        id = "47wNcpqEloYJEl8X0C0Zwa"
        fingerprint = "v1_sha256_b8aa25fbde4d9ca36656f583e7601118a06e57703862c8b28b273881eef504fe"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 69 6E 67 20 55 6E 6B 6E 6F 77 6E 20 4D 73 67 6C 6F 67 20 54 61 67 }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_013e07de {
    meta:
        id = "6BhUvhVknuihXo5OIdemI3"
        fingerprint = "v1_sha256_ce21de61f94d41aa3abb73b9391a4d9c8ddeea75f1a2b36be58111b70a9590fe"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 49 67 6E 6F 72 69 6E 67 20 42 61 64 20 58 44 43 43 20 4E 6F }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_0de95cab {
    meta:
        id = "2I57d9hrR9rdZ1hThCP3t6"
        fingerprint = "v1_sha256_adec3e1d3110bcc22262d5f1f2ad14a347616f4a809f29170a9fbb5d1669a4c3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "717bea3902109d1b1d57e57c26b81442c0705af774139cd73105b2994ab89514"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 41 52 52 45 43 4F 52 44 53 00 53 68 6F 77 20 49 6E 66 6F }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_711259e4 {
    meta:
        id = "3m2OJyzDTkc2uXObEP7Uw8"
        fingerprint = "v1_sha256_a71dbb979bc1f7671ab9958b6aa502e6ded4ee1c1b026080fd377eb772ebb1d5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 03 7E 2B 8B 45 C8 3D FF 00 00 00 77 21 8B 55 CC 81 FA FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_7478ddd9 {
    meta:
        id = "MUJ4ZkvgKyk0a4GChSU3a"
        fingerprint = "v1_sha256_e650ee830b735a11088b628e865cd40a15054437ca05849f2eaa7838eac152e3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "20e1509c23d7ef14b15823e4c56b9a590e70c5b7960a04e94b662fc34152266c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 80 FA 0F 74 10 80 FA 16 74 0B 80 FA 1F 74 06 C6 04 1E 2E 89 }
    condition:
        all of them
}

