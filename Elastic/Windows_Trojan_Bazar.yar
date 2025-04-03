rule Windows_Trojan_Bazar_711d59f6 {
    meta:
        id = "5LVbuPhWz4fOPzRwz2pC4y"
        fingerprint = "v1_sha256_3bde62b468c44bdc18878fd369a7f0cf06f7be64149587a11524f725fa875f69"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "f29253139dab900b763ef436931213387dc92e860b9d3abb7dcd46040ac28a0e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 0F 94 C3 41 0F 95 C0 83 FA 0A 0F 9C C1 83 FA 09 0F 9F C2 31 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Bazar_9dddea36 {
    meta:
        id = "25D40NBOa6A8sI580Ppsrw"
        fingerprint = "v1_sha256_cf88e2e896fce742ad3325d53523167d6eb42188309ed4e66f73601bbb85574e"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "63df43daa61f9a0fbea2e5409b8f0063f7af3363b6bc8d6984ce7e90c264727d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { C4 10 5B 5F 5E C3 41 56 56 57 55 53 48 83 EC 18 48 89 C8 48 }
    condition:
        all of them
}

rule Windows_Trojan_Bazar_3a2cc53b {
    meta:
        id = "32YqwU2vdXbaUwvOG14j09"
        fingerprint = "v1_sha256_8cde37be646dbcf7e7f5e3f28f0fe8c95480861c62fa2ee8cdd990859313756c"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "b057eb94e711995fd5fd6c57aa38a243575521b11b98734359658a7a9829b417"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 63 41 3C 45 33 ED 44 8B FA 48 8B F9 8B 9C 08 88 00 00 00 44 8B A4 08 8C 00 }
    condition:
        all of them
}

rule Windows_Trojan_Bazar_de8d625a {
    meta:
        id = "3ng6YNnFzV0f6R69gDUxeJ"
        fingerprint = "v1_sha256_5fd7bb4ac818ec1b4bfcb7d236868a31b2f726182407c07c7f06c1d7e9c15d02"
        version = "1.0"
        date = "2022-01-14"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bazar"
        reference_sample = "1ad9ac4785b82c8bfa355c7343b9afc7b1f163471c41671ea2f9152a1b550f0c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F0 48 8B FA 48 8B D9 48 85 D2 74 61 4D 85 C0 74 5C 48 39 11 75 06 4C 39 41 08 74 2B 48 8B 49 }
    condition:
        all of them
}

