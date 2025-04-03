rule Windows_Trojan_Xeno_f92ffb82 {
    meta:
        id = "vbdjjucH7DEGGUGDxWyBx"
        fingerprint = "v1_sha256_17d5107b297c150cf737382c175e491e6bc4b17b2db583ff193f4acd40fdd459"
        version = "1.0"
        date = "2024-10-10"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Xeno"
        reference_sample = "22dbdbcdd4c8b6899006f9f07e87c19b6a2947eeff8cc89c653309379b388cf4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 28 00 00 0A 7D 0E 00 00 04 02 7B 0E 00 00 04 28 29 00 00 0A 07 7B 03 00 00 04 02 7B 0E 00 00 04 6F 2A 00 00 0A 3A F2 00 00 00 02 7B 07 00 00 04 02 7B 09 00 00 04 6F 32 00 00 06 6F 2B 00 00 0A }
    condition:
        all of them
}

rule Windows_Trojan_Xeno_89f9f060 {
    meta:
        id = "salekF0LSnkkLp5tPNpWo"
        fingerprint = "v1_sha256_a98bf8d1411449b41f0e35d368de3355ace837d9a406eee4f8fb087737eb283e"
        version = "1.0"
        date = "2024-10-25"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Xeno"
        reference_sample = "b74733d68e95220ab0630a68ddf973b0c959fd421628e639c1b91e465ba9299b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $sc_1 = { 8B 44 24 04 89 C6 FF 56 08 68 00 04 00 00 6A 08 50 FF 16 89 C3 8B 06 89 83 2C 01 00 00 8B 46 04 89 83 30 01 00 00 8B 46 08 89 83 34 01 00 00 8B 46 0C 89 83 38 }
        $sc_2 = { 55 48 89 E5 48 83 EC 40 49 89 CC 41 FF 54 24 10 48 89 C1 BA 08 00 00 00 41 B8 00 04 00 00 41 FF 14 24 48 89 C3 49 8B 04 24 48 89 83 90 01 00 00 49 8B 44 24 08 }
        $str_1 = "SharpInjector" ascii fullword
        $str_2 = "HEAVENSGATE_NON_OPERATIONAL" ascii fullword
        $str_3 = "ChromeDecryptor" ascii fullword
        $str_4 = "DataExtractionStructs" ascii fullword
        $str_5 = "XenoStealer" ascii fullword
    condition:
        (($sc_1 or $sc_2) and ($str_1 or $str_2)) and (1 of ($str_3, $str_4, $str_5))
}

