rule Linux_Trojan_Setag_351eeb76 {
    meta:
        id = "5CrzF9kMw7LLCiBzQ7pD3V"
        fingerprint = "v1_sha256_3519d9e4bfa18c19b49d0fa15ef78151bd13db9614406c4569720d20830f3cbb"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Setag"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 04 8B 45 F8 C1 E0 02 01 C2 8B 45 EC 89 02 8D 45 F8 FF 00 8B }
    condition:
        all of them
}

rule Linux_Trojan_Setag_01e2f79b {
    meta:
        id = "3tkFdTPl2ONspdAjoFt3Ru"
        fingerprint = "v1_sha256_1e0336760f364acbbe0e8aec10bc7bfb48ed7e33cde56d8914617664cb93fd9b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Setag"
        reference_sample = "5b5e8486174026491341a750f6367959999bbacd3689215f59a62dbb13a45fcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 0C 8B 45 EC 89 45 FC 8D 55 E8 83 EC 04 8D 45 F8 50 8D 45 FC }
    condition:
        all of them
}

