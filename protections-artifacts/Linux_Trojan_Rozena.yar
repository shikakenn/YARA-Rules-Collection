rule Linux_Trojan_Rozena_56651c1d {
    meta:
        id = "20LbTqaLWK0LSviw8msy1d"
        fingerprint = "v1_sha256_a6d283b0c398cb1004defe7f5669f912112262e5aaf677ae4ca7fd15565cb988"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rozena"
        reference_sample = "997684fb438af3f5530b0066d2c9e0d066263ca9da269d6a7e160fa757a51e04"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E1 95 68 A4 1A 70 C7 57 FF D6 6A 10 51 55 FF D0 68 A4 AD }
    condition:
        all of them
}

