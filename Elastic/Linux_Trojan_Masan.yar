rule Linux_Trojan_Masan_5369c678 {
    meta:
        id = "2vHIkhZo4HMgkIzxp70aCz"
        fingerprint = "v1_sha256_e57b105004216a6054b0561b69cce00c35255c5bd33aa8e403d0a3967cd0697e"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Masan"
        reference_sample = "f2de9f39ca3910d5b383c245d8ca3c1bdf98e2309553599e0283062e0aeff17f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C0 89 45 E4 83 7D E4 FF 75 ?? 68 ?? 90 04 08 }
    condition:
        all of them
}

