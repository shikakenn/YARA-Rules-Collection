rule Linux_Trojan_Xhide_7f0a131b {
    meta:
        id = "1ii41r7SlsbnYz2w91hdYa"
        fingerprint = "v1_sha256_4843042576d1f4f37b5a7cda1b261831030d9145c49b57e9b4c66e2658cc8cf9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 85 68 FF FF FF 83 E0 40 85 C0 75 1A 8B 85 68 FF FF FF 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xhide_cd8489f7 {
    meta:
        id = "1l4djjxglIbLOZ5N0uupoq"
        fingerprint = "v1_sha256_34924260c811f1796ae37faec922bc21bb312ebb0672042d3ec27855f63ed61e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6F 74 2E 63 6F 6E 66 0A 0A 00 46 75 6C 6C 20 70 61 74 68 20 }
    condition:
        all of them
}

rule Linux_Trojan_Xhide_840b27c7 {
    meta:
        id = "Moj5XiCLlkshSrRKAsnMU"
        fingerprint = "v1_sha256_6b0bfe69558399af6e0469a31741dcf2eb91fbe3e130267139240d3458eb8a0d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 45 98 83 E0 40 85 C0 75 16 8B 45 98 83 E0 08 85 C0 75 0C 8B }
    condition:
        all of them
}

