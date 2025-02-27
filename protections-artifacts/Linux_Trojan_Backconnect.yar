rule Linux_Trojan_Backconnect_c6803b39 {
    meta:
        id = "58vbrMOuYTFSAIVsyWFptC"
        fingerprint = "v1_sha256_02750b2788c2912bba0fc8594f6a12c75ce1f41d1075acf7c920f6e616ab65c7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Backconnect"
        reference_sample = "a5e6b084cdabe9a4557b5ff8b2313db6c3bb4ba424d107474024030115eeaa0f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 78 3A 48 98 48 01 C3 49 01 C5 48 83 FB 33 76 DC 31 C9 BA 10 00 }
    condition:
        all of them
}

