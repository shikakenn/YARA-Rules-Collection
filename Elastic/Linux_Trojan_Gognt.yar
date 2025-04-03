rule Linux_Trojan_Gognt_50c3d9da {
    meta:
        id = "6ujSzqNu238Vx32PRenT0H"
        fingerprint = "v1_sha256_ecd9cd94b3bf8c50c347e70aab3da03ea6589530b20941a9f62dac501f8144fc"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gognt"
        reference_sample = "79602bc786edda7017c5f576814b683fba41e4cb4cf3f837e963c6d0d42c50ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 47 6F 00 00 51 76 46 5F 6F 30 59 36 55 72 5F 6C 63 44 }
    condition:
        all of them
}

rule Linux_Trojan_Gognt_05b10f4b {
    meta:
        id = "1hj1y6ahsYFNSngg0focam"
        fingerprint = "v1_sha256_1dfc3417f75aa81aea5eda3d6da076f1cacf82dbfc039252b1d16f52b81a5a65"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Gognt"
        reference_sample = "e43aaf2345dbb5c303d5a5e53cd2e2e84338d12f69ad809865f20fd1a5c2716f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 7C 24 78 4C 89 84 24 A8 00 00 00 48 29 D7 49 89 F9 48 F7 DF 48 C1 }
    condition:
        all of them
}

