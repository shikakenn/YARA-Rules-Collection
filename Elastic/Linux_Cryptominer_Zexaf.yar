rule Linux_Cryptominer_Zexaf_b90e7683 {
    meta:
        id = "1mug8lDPYTGMW93MycVbhG"
        fingerprint = "v1_sha256_d8485d8fbf00d5c828d7c6c80fef61f228f308e3d27a762514cfb3f00053b30b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Zexaf"
        reference_sample = "98650ebb7e463a06e737bcea4fd2b0f9036fafb0638ba8f002e6fe141b9fecfe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 F2 C1 E7 18 C1 E2 18 C1 ED 08 09 D5 C1 EE 08 8B 14 24 09 FE }
    condition:
        all of them
}

