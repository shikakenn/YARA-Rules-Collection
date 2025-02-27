rule Linux_Trojan_Sqlexp_1aa5001e {
    meta:
        id = "6KSynswXoh4GZAD0MAMU94"
        fingerprint = "v1_sha256_48c7331c80aa7d918f46d282c6f38b8e780f9b5222cf9304bf1a8bb39cc129ab"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sqlexp"
        reference_sample = "714a520fc69c54bcd422e75f4c3b71ce636cfae7fcec3c5c413d1294747d2dd6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E3 52 53 89 E1 B0 0B CD 80 00 00 ?? 00 }
    condition:
        all of them
}

