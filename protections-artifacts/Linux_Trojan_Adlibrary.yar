rule Linux_Trojan_Adlibrary_2e908e5f {
    meta:
        id = "1VxzAChrgExBkmtz6ooruG"
        fingerprint = "v1_sha256_0d0df636876adf0268b7a409bfc9d8bfad298793d11297596ef91aeba86889da"
        version = "1.0"
        date = "2022-08-23"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Adlibrary"
        reference_sample = "acb22b88ecfb31664dc07b2cb3490b78d949cd35a67f3fdcd65b1a4335f728f1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 32 04 39 83 C7 01 0F BE C0 89 04 24 E8 ?? ?? ?? ?? 3B 7C 24 ?? B8 00 00 00 00 0F 44 F8 83 C5 01 81 FD }
    condition:
        all of them
}

