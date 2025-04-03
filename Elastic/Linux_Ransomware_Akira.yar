rule Linux_Ransomware_Akira_02237952 {
    meta:
        id = "1fWFIxlFkdsf94P5oSwZAZ"
        fingerprint = "v1_sha256_a9b3cdddb3387251d7da90f32b08b9c1eedcdff1fe90d51f4732183666a6d467"
        version = "1.0"
        date = "2023-07-28"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Akira"
        reference_sample = "1d3b5c650533d13c81e325972a912e3ff8776e36e18bca966dae50735f8ab296"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "No path to encrypt" fullword
        $a2 = "--encryption_percent" fullword
        $a3 = "Failed to import public key" fullword
        $a4 = "akira_readme.txt" fullword
    condition:
        3 of them
}

rule Linux_Ransomware_Akira_27440619 {
    meta:
        id = "37AW64Pf1iEvUON5grZQD2"
        fingerprint = "v1_sha256_d2bb413b5919b3ed6239fbc714d025d2ddc321cb8a0b310aaae48b0869810be8"
        version = "1.0"
        date = "2024-11-21"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Akira"
        reference_sample = "3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 83 A7 00 01 00 00 00 31 C0 41 88 87 04 01 00 00 6A 08 5B 49 89 9F 08 01 00 00 0F 57 C0 41 0F 29 87 10 01 00 00 49 89 9F 20 01 00 00 41 0F 11 87 28 01 00 00 41 C6 87 38 01 00 00 01 6A 01 41 5E }
    condition:
        all of them
}

