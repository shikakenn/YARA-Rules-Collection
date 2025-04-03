rule Linux_Ransomware_ItsSoEasy_30bd68e0 {
    meta:
        id = "2LGnd21rpYzvOQ91j0Pomb"
        fingerprint = "v1_sha256_a8838af442d1106bc9a7df93d6d8335ff0275bf5928acbb605e9bad58ce6bbd4"
        version = "1.0"
        date = "2023-07-28"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.ItsSoEasy"
        reference_sample = "efb1024654e86c0c30d2ac5f97d27f5f27b4dd3f7f6ada65d58691f0d703461c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 44 61 74 61 2E 66 75 6E 63 31 }
        $a2 = { 6D 61 69 6E 2E 6D 61 6B 65 41 75 74 6F 52 75 6E }
    condition:
        all of them
}

