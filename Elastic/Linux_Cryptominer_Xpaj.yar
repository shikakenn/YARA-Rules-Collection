rule Linux_Cryptominer_Xpaj_fdbd614e {
    meta:
        id = "3LqehIOdYNdXYZldBOULps"
        fingerprint = "v1_sha256_70e6450f98411750361481aaad0d3ea079f58b1ae09970f04da09c20137a50fa"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Xpaj"
        reference_sample = "3e2b1b36981713217301dd02db33fb01458b3ff47f28dfdc795d8d1d332f13ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 72 72 6F 72 3A 20 47 65 74 25 73 20 74 65 6D 70 20 72 65 74 75 }
    condition:
        all of them
}

