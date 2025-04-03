rule Linux_Trojan_Lady_75f6392c {
    meta:
        id = "3mV9KTf1ljG66q2iwLDUA1"
        fingerprint = "v1_sha256_5160b6ab4800c72b48b501787f3164c2ba1061a2abe21c63180e02d6791a4c12"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Lady"
        reference_sample = "c257ac7bd3a9639e0d67a7db603d5bc8d8505f6f2107a26c2615c5838cf11826"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 57 72 69 00 49 3B 66 10 76 38 48 83 EC 18 48 89 6C 24 10 48 8D 6C }
    condition:
        all of them
}

