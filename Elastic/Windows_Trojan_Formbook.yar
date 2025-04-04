rule Windows_Trojan_Formbook_1112e116 {
    meta:
        id = "27DXnnKMEbImLUEQy7agrP"
        fingerprint = "v1_sha256_ec307a8681fa01fc0c7c0579b0e3eff10e7f373159ad58dae0a358ff16fbc10b"
        version = "1.0"
        date = "2021-06-14"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        threat_name = "Windows.Trojan.Formbook"
        reference_sample = "6246f3b89f0e4913abd88ae535ae3597865270f58201dc7f8ec0c87f15ff370a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 3C 30 50 4F 53 54 74 09 40 }
        $a2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
        $a3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
        $a4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }
    condition:
        any of them
}

rule Windows_Trojan_Formbook_772cc62d {
    meta:
        id = "6n8Z8n7wvL4M1FT6eM1DRB"
        fingerprint = "v1_sha256_db9ab8df029856fc1c210499ed8e1b92c9722f7aa2264363670c47b51ec8fa83"
        version = "1.0"
        date = "2022-05-23"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        threat_name = "Windows.Trojan.Formbook"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
        $a2 = "signin"
        $a3 = "persistent"
        $r1 = /.\:\\Users\\[^\\]{1,50}\\AppData\\Roaming\\[a-zA-Z0-9]{8}\\[a-zA-Z0-9]{3}log\.ini/ wide
    condition:
        2 of ($a*) and $r1
}

rule Windows_Trojan_Formbook_5799d1f2 {
    meta:
        id = "6Ge5ZhU6eYY3mRRHthfAdF"
        fingerprint = "v1_sha256_8e61eabd11beb9fb35c016983cfb3085f5ceddfc8268522f3b48d20be5b5df6a"
        version = "1.0"
        date = "2022-06-08"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        threat_name = "Windows.Trojan.Formbook"
        reference_sample = "8555a6d313cb17f958fc2e08d6c042aaff9ceda967f8598ac65ab6333d14efd9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { E9 C5 9C FF FF C3 E8 00 00 00 00 58 C3 68 }
    condition:
        all of them
}

