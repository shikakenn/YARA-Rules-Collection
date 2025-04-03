rule Linux_Trojan_Connectback_bf194c93 {
    meta:
        id = "6b8f5yEcKfmBRfOWPGrWUE"
        fingerprint = "v1_sha256_148626e05caee4a2b2542726ea4e4dab074eeab0572a65fdbd32f5d96544daf8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Connectback"
        reference_sample = "6784cb86460bddf1226f71f5f5361463cbda487f813d19cd88e8a4a1eb1a417b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { B6 0C B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

