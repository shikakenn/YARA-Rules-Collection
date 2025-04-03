rule Linux_Trojan_Ipstorm_3c43d4a7 {
    meta:
        id = "7lhWgpu1zvPMtjoxLrzLX8"
        fingerprint = "v1_sha256_c7e9191312197f8925d7231d0b8badf8b5ca35685df909c0d1feb301b4385d7b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 8D 54 24 58 31 F6 EB 11 48 8B 84 24 88 00 00 00 48 89 F1 48 }
    condition:
        all of them
}

rule Linux_Trojan_Ipstorm_f9269f00 {
    meta:
        id = "47VcRuqHSxrCWfdRIygPW8"
        fingerprint = "v1_sha256_5914d222b49aaf6c1040e48ffd93c04bd5df25f1d97bde79b034862fca6555f6"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 B8 69 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ipstorm_08bcf61c {
    meta:
        id = "6OkrV9EwnCYmrrKauwHPJ"
        fingerprint = "v1_sha256_fb2755c04b61d19788a92b8c9c1c9eb2552b62b27011e302840fdcf689b3d9b4"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "503f293d84de4f2c826f81a68180ad869e0d1448ea6c0dbf09a7b23801e1a9b9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8C 24 98 00 00 00 31 D2 31 DB EB 04 48 83 C1 18 48 8B 31 48 83 79 }
    condition:
        all of them
}

