rule Linux_Cryptominer_Minertr_9901e275 {
    meta:
        id = "6rgTgtzNWVQ7QRbgSP30b1"
        fingerprint = "v1_sha256_a18e0763fe9aec6d89b39cefb872b1751727e2d88ec4733b9c8b443b83219763"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Minertr"
        reference_sample = "f77246a93782fd8ee40f12659f41fccc5012a429a8600f332c67a7c2669e4e8f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 56 41 55 41 54 55 53 48 83 EC 78 48 89 3C 24 89 F3 89 74 }
    condition:
        all of them
}

