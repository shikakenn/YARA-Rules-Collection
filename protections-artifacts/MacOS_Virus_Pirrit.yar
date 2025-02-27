rule MacOS_Virus_Pirrit_271b8ed0 {
    meta:
        id = "1XGHfZBNUCfBuZtSjiqshP"
        fingerprint = "v1_sha256_cb77f6df1403afbc7f45d30551559b6de7eb1c3434778b46d31754da0a1b1f10"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Virus.Pirrit"
        reference_sample = "7feda05d41b09c06a08c167c7f4dde597ac775c54bf0d74a82aa533644035177"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 35 4A 6A 00 00 32 80 35 44 6A 00 00 75 80 35 3E 6A 00 00 1F 80 35 38 6A 00 00 }
    condition:
        all of them
}

