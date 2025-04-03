rule Multi_AttackSimulation_Blindspot_d93f54c5 {
    meta:
        id = "5XfS8aH81XXFReWZE23LMD"
        fingerprint = "v1_sha256_41984a0ad20ab21186252bb2f3f68604d2cbeea0e1ce22895dd163f7acbf2ca1"
        version = "1.0"
        date = "2022-05-23"
        modified = "2022-08-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.AttackSimulation.Blindspot"
        severity = 1
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a = "\\\\.\\pipe\\blindspot-%d."
    condition:
        all of them
}

