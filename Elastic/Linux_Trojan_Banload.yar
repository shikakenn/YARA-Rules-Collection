rule Linux_Trojan_Banload_d5e1c189 {
    meta:
        id = "6U89P3WyJ2sLNoCsjwaFdv"
        fingerprint = "v1_sha256_3f0bee251152a8c835a3bf71dc33c2e150705713c50ca2cfdbeb69361ed91a09"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Banload"
        reference_sample = "48bf0403f777db5da9c6a7eada17ad4ddf471bd73ea6cf02817dd202b49204f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E4 E4 E4 58 88 60 90 E4 E4 E4 E4 68 98 70 A0 E4 E4 E4 E4 78 }
    condition:
        all of them
}

