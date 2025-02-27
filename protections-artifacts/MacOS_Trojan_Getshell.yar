rule MacOS_Trojan_Getshell_f339d74c {
    meta:
        id = "64l37s97TS8i9GdaEq6471"
        fingerprint = "v1_sha256_77a409f1a0ab5f87a77a6b2ffa2d4ff7bd6d86c0f685c524e2083585bb3fb764"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Getshell"
        reference_sample = "b2199c15500728a522c04320aee000938f7eb69d751a55d7e51a2806d8cd0fe7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 00 00 FF E0 E8 00 00 00 00 58 8B 80 4B 22 00 00 FF E0 55 89 E5 53 83 EC 04 E8 }
    condition:
        all of them
}

