rule Linux_Ransomware_Gonnacry_53c3832d {
    meta:
        id = "3Ods6dblrfBMW66aKIBmn8"
        fingerprint = "v1_sha256_2b7453c4eb71b71e6a241f728b077a2ee63d988d55a64fedf61c34222799e262"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Gonnacry"
        reference_sample = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 48 89 E5 48 83 EC 10 48 89 7D F8 EB 56 48 8B 45 F8 48 8B }
    condition:
        all of them
}

