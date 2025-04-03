rule Linux_Trojan_Pnscan_20e34e35 {
    meta:
        id = "2smb2LgX68FsRpQvHvlcwQ"
        fingerprint = "v1_sha256_1e69ef50d25ffd0f38ed0eb81ab3295822aa183c5e06f307caf02826b1dfa011"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Pnscan"
        reference_sample = "7dbd5b709f16296ba7dac66dc35b9c3373cf88452396d79d0c92d7502c1b0005"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4C 00 54 45 4C 20 3A 20 00 3C 49 41 43 3E 00 3C 44 4F 4E 54 3E 00 }
    condition:
        all of them
}

