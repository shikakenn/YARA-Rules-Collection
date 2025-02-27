rule Windows_Trojan_Mata_3f3c563d {
    meta:
        id = "4V86SqO8YzYN3I6gPMe9wk"
        fingerprint = "v1_sha256_f1c41b0cc3dd25ae497dbb0bf124789c5c8d959da1121667e2d850fbcd4ca2c2"
        version = "1.0"
        date = "2024-12-16"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Mata"
        reference_sample = "5d1c95d0c827fe89897ae32d39d61fe9406306a753b07c19da6c00c066023391"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 41 8B C7 85 D2 B9 08 00 00 00 0F 94 C0 83 FA 01 0F 44 C1 41 3B D5 B9 10 00 00 00 41 0F 44 C5 83 FA 03 41 0F 44 C6 41 3B D6 0F 44 C1 83 FA 05 B9 80 00 00 00 0F 44 C1 83 FA 06 B9 20 00 00 00 0F 44 C1 83 FA 07 B9 40 00 00 00 0F 44 C1 44 8B F0 41 0F BA EE 09 }
    condition:
        all of them
}

