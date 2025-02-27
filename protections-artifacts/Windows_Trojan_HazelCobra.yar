rule Windows_Trojan_HazelCobra_6a9fe48a {
    meta:
        id = "WodKRSO0xOZ7EnPSr5m5v"
        fingerprint = "v1_sha256_dc4d561497c2e3da270d305ceaf3194b48d64c0d8e212ee6f03a2d89c8e006e8"
        version = "1.0"
        date = "2023-11-01"
        modified = "2023-11-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.HazelCobra"
        reference_sample = "b5acf14cdac40be590318dee95425d0746e85b1b7b1cbd14da66f21f2522bf4d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 E9 37 48 63 C2 F6 C2 01 75 0C C0 E1 04 48 D1 F8 88 4C 04 40 EB 07 }
        $s1 = "Data file loaded. Running..." fullword
        $s2 = "No key in args" fullword
        $s3 = "Can't read data file" fullword
    condition:
        $a1 or all of ($s*)
}

