rule Windows_Ransomware_Cuba_e64a16b1 {
    meta:
        id = "1tDHK9oTgJjYhDL6hA7ilD"
        fingerprint = "v1_sha256_915425ad49f1b9ebde114f92155d5969ec707304403f46d891d014b399165a4d"
        version = "1.0"
        date = "2021-08-04"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/cuba-ransomware-campaign-analysis"
        threat_name = "Windows.Ransomware.Cuba"
        reference_sample = "33352a38454cfc247bc7465bf177f5f97d7fd0bd220103d4422c8ec45b4d3d0e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 45 EC 8B F9 8B 45 14 89 45 F0 8D 45 E4 50 8D 45 F8 66 0F 13 }
        $HeaderCheck = { 8B 06 81 38 46 49 44 45 75 ?? 81 78 04 4C 2E 43 41 74 }
    condition:
        any of them
}

rule Windows_Ransomware_Cuba_95a98e69 {
    meta:
        id = "3kgBtLRr6hg5vA6goxXEjl"
        fingerprint = "v1_sha256_d17ef93943e826613be4c21ad1e41d1daa33db9da0fa6106bb8ba6334ebe1d08"
        version = "1.0"
        date = "2021-08-04"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/cuba-ransomware-campaign-analysis"
        threat_name = "Windows.Ransomware.Cuba"
        reference_sample = "00f18713f860dc8394fb23a1a2b6280d1eb2f20a487c175433a7b495a1ba408d"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "We also inform that your databases, ftp server and file server were downloaded by us to our servers." ascii fullword
        $a2 = "Good day. All your files are encrypted. For decryption contact us." ascii fullword
        $a3 = ".cuba" wide fullword
    condition:
        all of them
}

