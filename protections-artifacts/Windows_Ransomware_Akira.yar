rule Windows_Ransomware_Akira_c8c298ba {
    meta:
        id = "55dEAtgvSIF0btSxUDEp9V"
        fingerprint = "v1_sha256_9058c83693e93f6daee8894453e56e0d9a4867d551ec3a6b66d7a517f65d8b07"
        version = "1.0"
        date = "2024-05-02"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Akira"
        reference_sample = "a2df5477cf924bd41241a3326060cc2f913aff2379858b148ddec455e4da67bc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "akira_readme.txt" ascii fullword
        $a2 = "Number of threads to encrypt = " ascii fullword
        $a3 = "write_encrypt_info error:" ascii fullword
        $a4 = "Log-%d-%m-%Y-%H-%M-%S" ascii fullword
        $a5 = "--encryption_path" wide fullword
        $a6 = "--encryption_percent" wide fullword
    condition:
        3 of them
}

