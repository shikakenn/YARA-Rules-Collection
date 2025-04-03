rule Linux_Trojan_Merlin_55beddd3 {
    meta:
        id = "5QoH2XU1oNoLsrl63CT5sX"
        fingerprint = "v1_sha256_293158c981463544abd0c38694bfc8635ad1a679bbae115521b65879f145cea6"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "15ccdf2b948fe6bd3d3a7f5370e72cf3badec83f0ec7f47cdf116990fb551adf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }
    condition:
        all of them
}

rule Linux_Trojan_Merlin_bbad69b8 {
    meta:
        id = "1CgEpWPvbnDZbVCKhxi9qy"
        fingerprint = "v1_sha256_e18079c9f018dc8d7f2fdf5c950b405f9f84ad2a5b18775dbef829fe1cb770c3"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { DA 31 C0 BB 1F 00 00 00 EB 12 0F B6 3C 13 40 88 3C 02 40 88 }
    condition:
        all of them
}

rule Linux_Trojan_Merlin_c6097296 {
    meta:
        id = "aECcNcSVknagmwRwyQjeH"
        fingerprint = "v1_sha256_f48ed7f19ab29633600fde4bfea274bf36e7f60d700c9806b334d38a51d28b92"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 24 38 48 89 5C 24 48 48 85 C9 75 62 48 85 D2 75 30 48 89 9C 24 C8 00 }
    condition:
        all of them
}

