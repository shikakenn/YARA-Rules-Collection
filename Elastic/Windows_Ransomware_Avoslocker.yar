rule Windows_Ransomware_Avoslocker_7ae4d4f2 {
    meta:
        id = "5AKkhud3uzFcpJzojM7hDt"
        fingerprint = "v1_sha256_c87faf6f128fd6a8cabd68ec8de72fb10e6be42bdbe23ece374dd8f3cf0c1b15"
        version = "1.0"
        date = "2021-07-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Avoslocker"
        reference_sample = "43b7a60c0ef8b4af001f45a0c57410b7374b1d75a6811e0dfc86e4d60f503856"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "drive %s took %f seconds" ascii fullword
        $a2 = "client_rsa_priv: %s" ascii fullword
        $a3 = "drive: %s" ascii fullword
        $a4 = "Map: %s" ascii fullword
        $a5 = "encrypting %ls failed" wide fullword
    condition:
        all of them
}

