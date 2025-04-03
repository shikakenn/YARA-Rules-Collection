rule Windows_Virus_Expiro_84e99ff0 {
    meta:
        id = "1DcgN3rEfkAOywb9wED2dz"
        fingerprint = "v1_sha256_ce4847bf5850c1f30dca9603bfbbfbb69339285f096ac469c6d2d4b04f5562b4"
        version = "1.0"
        date = "2023-09-26"
        modified = "2023-11-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Virus.Expiro"
        reference_sample = "47107836ead700bddbe9e8a0c016b5b1443c785442b2addbb50a70445779bad7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 50 51 52 53 55 56 57 E8 00 00 00 00 5B 81 EB ?? ?? ?? 00 BA 00 00 00 00 53 81 }
        $a2 = { 81 C2 00 04 00 00 81 C3 00 04 00 00 }
    condition:
        all of them
}

