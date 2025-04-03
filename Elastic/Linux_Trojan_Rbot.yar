rule Linux_Trojan_Rbot_c69475e3 {
    meta:
        id = "4zA6Ju0lOkbSDP9DSh9QYX"
        fingerprint = "v1_sha256_2a8629ebf6e2082ce90f1b2130ae596e4e515f3289a25899f2fc57b99c01a654"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "9d97c69b65d2900c39ca012fe0486e6a6abceebb890cbb6d2e091bb90f6b9690"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 56 8B 76 20 03 F5 33 C9 49 41 AD 33 DB 36 0F BE 14 28 38 F2 }
    condition:
        all of them
}

rule Linux_Trojan_Rbot_96625c8c {
    meta:
        id = "5YzB08Jk9KUJdOH08Zg53p"
        fingerprint = "v1_sha256_5a9671e10e7b9b58ecf9fab231de18b4b6039c9d351b145fae1705297acda95e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "a052cfad3034d851c6fad62cc8f9c65bceedc73f3e6a37c9befe52720fd0890e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 28 8B 45 3C 8B 54 05 78 01 EA 8B 4A 18 8B 5A 20 01 EB E3 38 49 8B }
    condition:
        all of them
}

rule Linux_Trojan_Rbot_366f1599 {
    meta:
        id = "2Sn125goBCSHXj9YQuuYbE"
        fingerprint = "v1_sha256_3efe0f35efd855b415149513e8abb2210a26ef6f3b6c31275c8147fabb634fab"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "5553d154a0e02e7f97415299eeae78e5bb0ecfbf5454e3933d6fd9675d78b3eb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B }
    condition:
        all of them
}

