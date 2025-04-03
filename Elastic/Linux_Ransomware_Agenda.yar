rule Linux_Ransomware_Agenda_4562a654 {
    meta:
        id = "3nHT9RTeobvFjp4UskyBZa"
        fingerprint = "v1_sha256_9e9adad7640cda1142c31e801d1473e4ddb84574ce1bb1694e40d96850fcb815"
        version = "1.0"
        date = "2024-09-12"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Agenda"
        reference_sample = "cd27a31e618fe93df37603e5ece3352a91f27671ee73bdc8ce9ad793cad72a0f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $ = "%s_RECOVER.txt"
        $ = "-- Qilin"
        $ = "no-vm-kill"
        $ = "File extensions blacklist: [%s]"
    condition:
        3 of them
}

