rule Linux_Ransomware_EchoRaix_ea9532df {
    meta:
        id = "77fSkvtirAP8pxfOuKHmHh"
        fingerprint = "v1_sha256_4944f5a2632bfe0abebfa6f658ed3f71e4d97efcb428ed0987e2071dfd66e6a9"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.EchoRaix"
        reference_sample = "dfe32d97eb48fb2afc295eecfda3196cba5d27ced6217532d119a764071c6297"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 43 58 68 64 4B 74 7A 65 42 59 6C 48 65 58 79 5A 52 62 61 30 2F 6E 65 46 7A 34 49 7A 67 53 38 4C 68 75 36 38 5A 75 4C 4C 52 2F 66 67 6E 72 34 79 54 72 5A 54 6B 43 36 31 62 2D 59 6F 6C 49 2F 32 4C 36 66 53 55 46 52 72 55 70 49 34 6D 4E 53 41 4F 62 5F }
    condition:
        all of them
}

rule Linux_Ransomware_EchoRaix_ee0c719a {
    meta:
        id = "1gZ2eqQGPVBjJvnzLvLdBL"
        fingerprint = "v1_sha256_3ca12ea0f1794935ea570dda83f33d04ffb19b6664cc1c8b1cbeed59ac04a01a"
        version = "1.0"
        date = "2023-07-29"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.EchoRaix"
        reference_sample = "e711b2d9323582aa390cf34846a2064457ae065c7d2ee1a78f5ed0859b40f9c0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 24 10 89 44 24 68 8B 4C 24 14 8B 54 24 18 85 C9 74 57 74 03 8B }
        $a2 = { 6D 61 69 6E 2E 43 68 65 63 6B 49 73 52 75 6E 6E 69 6E 67 }
    condition:
        all of them
}

