rule Linux_Trojan_Psybnc_563ecb11 {
    meta:
        id = "3JPrmizwAgQOwd8dk6QlcU"
        fingerprint = "v1_sha256_b93e6ab097ccd4c348d228a48df098594e560e62256bfe019669ca9488221214"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 5F 65 6E 00 6B 6F 5F 65 6E 00 72 75 5F 65 6E 00 65 73 5F 65 6E 00 44 }
    condition:
        all of them
}

rule Linux_Trojan_Psybnc_ab3396d5 {
    meta:
        id = "53jaPcpX2kass16J1C0fNS"
        fingerprint = "v1_sha256_8c083f66fc252a88395bb954a67d710d64f5b68efb9df4b60b260302874b400a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "c5ec84e7cc891af25d6319abb07b1cedd90b04cbb6c8656c60bcb07e60f0b620"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 53 54 00 55 53 45 52 4F 4E 00 30 00 50 25 64 00 58 30 31 00 }
    condition:
        all of them
}

rule Linux_Trojan_Psybnc_f07357f1 {
    meta:
        id = "6kzdNZHQQN4ac1t9MBfpra"
        fingerprint = "v1_sha256_cfe217fe108de787600d1ef06ac6738d84aedfc46e5632143692a9f83cb62df7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F7 EA 89 D0 C1 F8 02 89 CF C1 FF 1F 29 F8 8D 04 80 01 C0 29 C1 8D }
    condition:
        all of them
}

