rule Multi_Hacktool_SuperShell_f7486598 {
    meta:
        id = "7TGX9NXC2dYbG7MG4gC1tl"
        fingerprint = "v1_sha256_8c2c3f13fad03ece29f7f3fd12e22807b61ecdc16dee00b6430b915631554cff"
        version = "1.0"
        date = "2024-09-12"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Hacktool.SuperShell"
        reference_sample = "18556a794f5d47f93d375e257fa94b9fb1088f3021cf79cc955eb4c1813a95da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a = "NHAS/reverse_ssh/internal/terminal"
        $b1 = "foreground|fingerprint|proxy|process_name"
        $b2 = "Failed to kill shell"
        $b3 = "Missing listening address"
    condition:
        $a and 1 of ($b*)
}

