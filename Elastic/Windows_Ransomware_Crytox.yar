rule Windows_Ransomware_Crytox_29859242 {
    meta:
        id = "5YwMlZJbmog3RUimaKsw5w"
        fingerprint = "v1_sha256_47ca96e14b2b56bc6ef1ed22b42adac7aa557170632c2dc085fae3baf6198f40"
        version = "1.0"
        date = "2024-01-18"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Crytox"
        reference_sample = "55a27cb6280f31c077987d338151b13e9dc0cc1c14d47a32e64de6d6c1a6a742"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 83 C7 20 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 08 D7 C1 C8 10 33 C2 33 47 E0 D0 E2 }
    condition:
        all of them
}

