rule Windows_Trojan_Fickerstealer_cc02e75e {
    meta:
        id = "3mLihSn0qcd6uwOYQpIHdk"
        fingerprint = "v1_sha256_ccfd7edf7625c13eea5b88fa29f9b8d3d873688f328f3e52c0500ac722c84511"
        version = "1.0"
        date = "2021-07-22"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Fickerstealer"
        reference_sample = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
        severity = 80
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" ascii fullword
        $a2 = "\"SomeNone" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Fickerstealer_f2159bec {
    meta:
        id = "7A7imxRM3hYP1TLzdCvbgD"
        fingerprint = "v1_sha256_d36cb90b526a291858291d615272baa78881309c83376f4d4cce1768c740ddbc"
        version = "1.0"
        date = "2021-07-22"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Fickerstealer"
        reference_sample = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 10 12 F2 0F 10 5A 08 31 C1 89 C6 8B 42 50 89 7D F0 F2 0F 11 8D 18 FF }
    condition:
        all of them
}

