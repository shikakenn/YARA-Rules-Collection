rule Linux_Ransomware_Hive_bdc7de59 {
    meta:
        id = "1RrGt8FE5CQP6hf3jZpNNT"
        fingerprint = "v1_sha256_33908128258843d63c5dfe5acf15cfd68463f5cbdf08b88ef1bba394058a5a92"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Hive"
        reference_sample = "713b699c04f21000fca981e698e1046d4595f423bd5741d712fd7e0bc358c771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 40 03 4C 39 C1 73 3A 4C 89 84 24 F0 00 00 00 48 89 D3 48 89 CF 4C }
    condition:
        all of them
}

