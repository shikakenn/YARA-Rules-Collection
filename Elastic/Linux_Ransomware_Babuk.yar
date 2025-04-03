rule Linux_Ransomware_Babuk_bd216cab {
    meta:
        id = "bdf3w8u3a3pQTTNX24yax"
        fingerprint = "v1_sha256_b0538be9d8deccc3f77640da28e5fd38a07557e9e5e3c09b11349d7eb50a56b5"
        version = "1.0"
        date = "2024-05-09"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Babuk"
        reference_sample = "d305a30017baef4f08cee38a851b57869676e45c66e64bb7cc58d40bf0142fe0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "Whole files count: %d"
        $a2 = "Doesn't encrypted files: %d"
    condition:
        all of them
}

