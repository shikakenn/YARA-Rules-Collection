rule Windows_Trojan_SourShark_f0247cce {
    meta:
        id = "2cIEzbSdwVYb0tb2DBadFH"
        fingerprint = "v1_sha256_0c5d802b5bfc771bdf5df541b18c7ab9de4f420fd3928bfd85b1a71cca2af1bc"
        version = "1.0"
        date = "2024-06-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SourShark"
        reference_sample = "07eb88c69437ee6e3ea2fbab5f2fbd8e846125d18c1da7d72bb462e9d083c9fc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%s\\svchost.%s"
        $a2 = "crypto_domain"
        $a3 = "postback_id"
    condition:
        all of them
}

rule Windows_Trojan_SourShark_adee8a17 {
    meta:
        id = "2EZ80zPfOd9ZVxvyYpsn5V"
        fingerprint = "v1_sha256_98a4d31849a1828c2154b5032a81580f5dcc8d4a65b96dea3a727e2a82a51666"
        version = "1.0"
        date = "2024-06-04"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SourShark"
        reference_sample = "07eb88c69437ee6e3ea2fbab5f2fbd8e846125d18c1da7d72bb462e9d083c9fc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 8B 45 08 8B 4C BE 08 8A 04 02 02 C3 02 C1 0F B6 D8 8B 44 9E 08 89 44 BE 08 8D 42 01 33 D2 89 4C 9E 08 47 83 F8 20 0F 4C D0 81 FF 00 01 00 00 7C CF 8B 16 33 FF 8B 5E 04 39 7D FC 7E 33 0F 1F 00 }
    condition:
        all of them
}

