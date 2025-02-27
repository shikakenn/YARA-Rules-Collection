rule Linux_Ransomware_NoEscape_6de58e0c {
    meta:
        id = "5OCygR14olP4RdRU5QvMIb"
        fingerprint = "v1_sha256_c275d0cfdadcaabe57c432956e96b4bb344d947899fa5ad55b872e02b4d44274"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.NoEscape"
        reference_sample = "46f1a4c77896f38a387f785b2af535f8c29d40a105b63a259d295cb14d36a561"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "HOW_TO_RECOVER_FILES.txt"
        $a2 = "large_file_size_mb"
        $a3 = "note_text"
    condition:
        all of them
}

