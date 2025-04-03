rule MacOS_Virus_Vsearch_0dd3ec6f {
    meta:
        id = "16EJ4xVICaLdbiZXlTRD3u"
        fingerprint = "v1_sha256_17a467b000117ea6c39fbd40b502ac9c7d59a97408c2cdfb09c65b2bb09924e5"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Virus.Vsearch"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 2F 00 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6D 00 2F 4D 61 63 69 6E 74 6F 73 }
    condition:
        all of them
}

rule MacOS_Virus_Vsearch_2a0419f8 {
    meta:
        id = "2Mg48o46FbCdqC65cHRSCO"
        fingerprint = "v1_sha256_fa9b811465e435bff5bc0f149ff65f57932c94f548a5ece4ec54ba775cdbb55a"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Virus.Vsearch"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 6F 72 6D 61 6C 2F 69 33 38 36 2F 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6F 00 }
    condition:
        all of them
}

