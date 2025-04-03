rule Linux_Rootkit_Adore_fe3fd09f {
    meta:
        id = "4VflG3RnmSzjVxNcKLlsKd"
        fingerprint = "v1_sha256_cc07efb9484562cd870649a38126f08aa4e99ed5ad4662ece0488d9ffd97520e"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Adore"
        reference_sample = "f4e532b840e279daf3d206e9214a1b065f97deb7c1487a34ac5cbd7cbbf33e1a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 00 75 17 68 E4 A1 04 08 }
    condition:
        all of them
}

