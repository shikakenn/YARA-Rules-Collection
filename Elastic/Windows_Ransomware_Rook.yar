rule Windows_Ransomware_Rook_ee21fa67 {
    meta:
        id = "5MSECDcStsV3DE5xZcR2sA"
        fingerprint = "v1_sha256_6fe19cfc572a3dceba5e26615d111a3c0fa1036e275a5640a5c5a8f8cdaf6dc1"
        version = "1.0"
        date = "2022-01-14"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Rook"
        reference_sample = "c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 01 75 09 8B C3 FF C3 48 89 74 C5 F0 48 FF C7 48 83 FF 1A 7C DB }
    condition:
        all of them
}

