rule Windows_Ransomware_Hive_55619cd0 {
    meta:
        id = "2otgpDDSMOCBy6APnEhf8P"
        fingerprint = "v1_sha256_51e2b03a9f9b92819bbf05ecbb33a23662a40e7d51f9812aa8243c4506057f1f"
        version = "1.0"
        date = "2021-08-26"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Hive"
        reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "google.com/encryptor.(*App).KillProcesses" ascii fullword
        $a2 = "- Do not shutdown or reboot your computers, unmount external storages." ascii fullword
        $a3 = "hive"
    condition:
        all of them
}

rule Windows_Ransomware_Hive_3ed67fe6 {
    meta:
        id = "ncU30fDRFLLgvTQXvQtT6"
        fingerprint = "v1_sha256_a599f0d528bdbec00afa7e9a5cddec5e799ee755a7f30af70dde7d2459b70155"
        version = "1.0"
        date = "2021-08-26"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Hive"
        reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "bmr|sql|oracle|postgres|redis|vss|backup|sstp"
        $a2 = "key.hive"
        $a3 = "Killing processes"
        $a4 = "Stopping services"
        $a5 = "Removing itself"
    condition:
        all of them
}

rule Windows_Ransomware_Hive_b97ec33b {
    meta:
        id = "5aAbmMNgdf05xZ9OughhrB"
        fingerprint = "v1_sha256_10034d9f53fd5099a423269e0c42c01eac18318f5d11599e1390912c8fd7af25"
        version = "1.0"
        date = "2021-08-26"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Hive"
        reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 74 C3 8B 44 24 78 8B 08 8B 50 04 8B 40 08 89 0C 24 89 54 24 04 89 44 }
    condition:
        all of them
}

