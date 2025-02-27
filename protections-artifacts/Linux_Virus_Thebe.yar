rule Linux_Virus_Thebe_1eb5985a {
    meta:
        id = "uVI0zrEIKK5hqblowMjWh"
        fingerprint = "v1_sha256_7d4bc4b1615048dec1f1fac599afa667e06ccb369bb1242b25887e0ce2a5066a"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Virus.Thebe"
        reference_sample = "30af289be070f4e0f8761f04fb44193a037ec1aab9cc029343a1a1f2a8d67670"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 42 31 C9 31 DB 31 F6 B0 1A CD 80 85 C0 0F 85 83 }
    condition:
        all of them
}

