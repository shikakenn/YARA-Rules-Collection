rule Linux_Hacktool_Portscan_a40c7ef0 {
    meta:
        id = "3vMC8usY1LQRgd19dH1nwd"
        fingerprint = "v1_sha256_6118ea86d628450e79ee658f4b95bae40080764a25240698d8ca7fcb7e6adaaf"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "c389c42bac5d4261dbca50c848f22c701df4c9a2c5877dc01e2eaa81300bdc29"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 54 50 44 00 52 65 73 70 6F 6E 73 65 20 77 61 73 20 4E 54 50 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_6c6000c2 {
    meta:
        id = "4pO7UPdDqJ5x0CV3aeTRuE"
        fingerprint = "v1_sha256_0cae81cbc0fdf48b4e7ac09865f05e2ad93d79b7a6f1af76a632727127ab050f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "8877009fc8ee27ba3b35a7680b80d21c84ee7296bcabe1de51aeeafcc8978da7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 30 B9 0E 00 00 00 4C 89 D7 F3 A6 0F 97 C2 80 DA 00 84 D2 45 0F }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_e191222d {
    meta:
        id = "3IohfQ5sW6D2YqbffaRnQv"
        fingerprint = "v1_sha256_6ffb2add4a76214ffd555cf1fe356371acd3638216094097b355670ecfe02ecd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "e2f4313538c3ef23adbfc50f37451c318bfd1ffd0e5aaa346cce4cc37417f812"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 46 4F 55 4E 44 00 56 41 4C 55 45 00 44 45 4C 45 54 45 44 00 54 }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_e57b0a0c {
    meta:
        id = "5eP90i4kz91sUBMtfILvbg"
        fingerprint = "v1_sha256_b2f67805e9381864591fdf61846284da97f8dd2f5c60484ce9c6e76d2f6f3872"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "f8ee385316b60ee551565876287c06d76ac5765f005ca584d1ca6da13a6eb619"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 83 7D 08 03 75 2B 83 EC 0C 8B 45 0C 83 C0 08 FF 30 8B 45 0C 83 }
    condition:
        all of them
}

