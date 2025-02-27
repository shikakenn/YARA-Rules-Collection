rule Linux_Trojan_Melofee_c23d18f3 {
    meta:
        id = "36fw5y0DpXTSRo62kK7fg1"
        fingerprint = "v1_sha256_fd769e0eca9ee858a3773a906189c510742364722b3e5c384158b3ec4158fc68"
        version = "1.0"
        date = "2024-11-14"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Melofee"
        reference_sample = "b0abf6691e769ead1f11cfdcd300f8cd5291f19059be6bb40d556f793b1bc21e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "hide ok"
        $str2 = "show ok"
        $str3 = "kill ok"
        $str4 = "wwwwwww"
        $str5 = "[md]"
        $str6 = "87JoENDi"
    condition:
        4 of them
}

