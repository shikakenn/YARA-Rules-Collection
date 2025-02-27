rule Multi_Ransomware_Akira_21842eb3 {
    meta:
        id = "4Gi6L8UJ2B4P8iFy5Ib09z"
        fingerprint = "v1_sha256_1c50f4da476cef9f9818f8c0117621eae232be0245ad244babe51d493f0a5a48"
        version = "1.0"
        date = "2024-11-21"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.Akira"
        reference_sample = "3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "Well, for now let's keep all the tears and resentment to ourselves"
    condition:
        all of them
}

