rule Linux_Rootkit_Dakkatoni_010d3ac2 {
    meta:
        id = "43CJtOPuCs9GkFtz7yWu6f"
        fingerprint = "v1_sha256_51119321f29aed695e09da22d3234eae96db93e8029d4525d018e56c7131f7b8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Dakkatoni"
        reference_sample = "38b2d033eb5ce87faa4faa7fcac943d9373e432e0d45e741a0c01d714ee9d4d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C8 C1 E0 0D 31 C1 89 CE 83 E6 03 83 C6 05 89 C8 31 D2 C1 }
    condition:
        all of them
}

