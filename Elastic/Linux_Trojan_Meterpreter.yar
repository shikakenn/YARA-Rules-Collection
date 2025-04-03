rule Linux_Trojan_Meterpreter_a82f5d21 {
    meta:
        id = "7m33zQ6Jd3Z04Lgp8DTEI1"
        fingerprint = "v1_sha256_d76886222de7292e8a76717f6d49452f52aaffb957bb0326bcfc7a35c3fdfc6a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 02 74 22 77 08 66 83 F8 01 74 20 EB 24 66 83 F8 03 74 0C 66 83 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_383c6708 {
    meta:
        id = "4B42yEjbHwRgveCU4zH4pA"
        fingerprint = "v1_sha256_b0fd479722ab0808a4709cbacbb874282c48a425f4dbdaec9f74bc7f839c82e4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Meterpreter"
        reference_sample = "d9d607f0bbc101f7f6dc0f16328bdd8f6ddb8ae83107b7eee34e1cc02072cb15"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_621054fe {
    meta:
        id = "odUCE8TSUFP1LWGPIkxTM"
        fingerprint = "v1_sha256_18f22bb0aa66ec2ecdaa9ca0e0d00ee59a2c9a3f231bd71915140e4464a4ea78"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 28 85 D2 75 0A 8B 50 2C 83 C8 FF 85 D2 74 03 8B 42 64 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_1bda891e {
    meta:
        id = "Z4fEbnTW2iX50N0PWIyEF"
        fingerprint = "v1_sha256_74e7547472117de20159f5b158cee0ccacc02a9aba5e5ad64a52c552c966d539"
        version = "1.0"
        date = "2021-12-13"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 11 62 08 F2 0F 5E D0 F2 0F 58 CB F2 0F 11 5A 10 F2 44 0F 5E C0 F2 0F }
    condition:
        all of them
}

