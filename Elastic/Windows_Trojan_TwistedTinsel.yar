rule Windows_Trojan_TwistedTinsel_aa56e527 {
    meta:
        id = "2VUxqOFm6lJQtCbJfOsXpK"
        fingerprint = "v1_sha256_de31d0a5560baf6b37897eba3a637b00b539f542a2620983c3407a6898e003c7"
        version = "1.0"
        date = "2023-12-06"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.TwistedTinsel"
        reference_sample = "ef1cbdf9a23ae028a858e1d09529982eaeda61197ae029e091918690d3a86e2e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 43 3A 5C 50 72 6F 67 72 61 6D 44 61 74 61 5C 4D 69 63 72 6F 73 6F 66 74 5C 45 64 67 65 55 70 64 61 74 65 5C 4C 6F 67 5C 63 68 75 61 6E 67 6B 6F 75 2E 6C 6F 67 }
        $a2 = { 55 8B EC 83 EC 20 C7 45 EC 01 00 00 00 8B 45 08 8B 48 04 89 4D F4 8B 55 08 8B 02 B9 08 00 00 00 C1 E1 00 8D 54 08 78 89 55 E4 8B 45 E4 83 78 04 00 0F 86 81 01 00 00 8B 4D E4 8B 55 F4 03 11 89 }
    condition:
        any of them
}

