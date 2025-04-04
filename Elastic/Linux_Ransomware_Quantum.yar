rule Linux_Ransomware_Quantum_8513fb8b {
    meta:
        id = "3aszy5xwgfYqh7X3yCxyP3"
        fingerprint = "v1_sha256_7e24be541bafc2427ecd8f76b7774fb65d7421bc300503eeb068b8104e168c70"
        version = "1.0"
        date = "2023-07-28"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Quantum"
        reference_sample = "3bcb9ad92fdca53195f390fc4d8d721b504b38deeda25c1189a909a7011406c9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "All your files are encrypted on all devices across the network"
        $a2 = "process with pid %d is blocking %s, going to kill it"
    condition:
        all of them
}

