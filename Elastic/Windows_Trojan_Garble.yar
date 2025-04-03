rule Windows_Trojan_Garble_eae7f2f7 {
    meta:
        id = "76EZYrrqiUbARlU5j9woTA"
        fingerprint = "v1_sha256_5d88579b0f0f71b8b4310c141fb243f39696e158227da0a1e0140b030b783c65"
        version = "1.0"
        date = "2022-06-08"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Garble"
        reference_sample = "4820a1ec99981e03675a86c4c01acba6838f04945b5f753770b3de4e253e1b8c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = ".\"G!-$G#-&J%.(G'-*G)-,J+..G--0G/-2J1.4G3-6G5-8J7.:G9-<G;->J=+@A?-BAA*DAC*FAE*HFG+JAI-LAK*NAM*PAO*RFQ+TAS-VAU9"
    condition:
        all of them
}

