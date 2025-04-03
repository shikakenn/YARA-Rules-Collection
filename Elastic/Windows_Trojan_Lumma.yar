rule Windows_Trojan_Lumma_693a5234 {
    meta:
        id = "4BcHlkpou6N1XG24wwH5rJ"
        fingerprint = "v1_sha256_2b29ac9bc73f191bdbfc92601cab923aa9f2f3380c8123ee469ced3754625dd0"
        version = "1.0"
        date = "2024-06-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Lumma"
        reference_sample = "88340abcdc3cfe7574ee044aea44808446daf3bb7bf9fc60b16a2b1360c5d9c0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 02 0F B7 16 83 C6 02 66 85 D2 75 EF 66 C7 00 00 00 0F B7 11 }
        $a2 = { 0C 0F B7 4C 24 04 66 89 0F 83 C7 02 39 F7 73 0C 01 C3 39 EB }
    condition:
        all of them
}

rule Windows_Trojan_Lumma_30608a8c {
    meta:
        id = "I41mEVdVZn6izFIWZk1V1"
        fingerprint = "v1_sha256_1793a535db3fd7e8ad3db4b2de22efffabbcd3e91d89f36de71e95dc0fa9012f"
        version = "1.0"
        date = "2024-10-07"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Lumma"
        reference_sample = "672e06b9729da0616b103c19d68b812bed33e3e12c788a584f13925f81d68129"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 8B 4C 24 04 8B 14 24 31 CA F7 D2 21 CA 29 D0 }
        $b = { 89 F1 C1 E9 0C 80 C9 E0 88 08 89 F1 C1 E9 06 80 E1 3F 80 C9 80 88 48 01 80 E2 3F }
    condition:
        any of them
}

rule Windows_Trojan_Lumma_4ad749b0 {
    meta:
        id = "PwvWaOCkwNopQCIJ59ehm"
        fingerprint = "v1_sha256_2248fe539cd0ba17073f1e1650fb93fb755ebe4bc2505e11aa7db9635a0fcb8e"
        version = "1.0"
        date = "2024-11-08"
        modified = "2024-11-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Lumma"
        reference_sample = "1f953271bc983b3a561b85083bc14a13d18b81a34855d0a6d9fe902934347f92"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 89 E5 83 E4 F8 83 EC 10 DD 45 08 DD 54 24 08 8B 4C 24 0C 89 CA C1 EA 14 81 E2 FF 07 00 00 81 FA FF 07 00 00 74 25 66 B8 FF FF 85 D2 75 31 DD 1C 24 B8 FF FF FF 7F 23 44 24 04 31 C9 0B 04 24 }
    condition:
        all of them
}

