rule Windows_Trojan_BloodAlchemy_3793364e {
    meta:
        id = "3qiDfbwepmj68Zky8o7tJG"
        fingerprint = "v1_sha256_c9f03767b92bb2c44f6b386e1f0a521f1a7a063cf73799844cc3423d4a7de7be"
        version = "1.0"
        date = "2023-09-25"
        modified = "2023-09-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        threat_name = "Windows.Trojan.BloodAlchemy"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 51 83 65 FC 00 53 56 57 BF 00 20 00 00 57 6A 40 FF 15 }
        $a2 = { 55 8B EC 81 EC 80 00 00 00 53 56 57 33 FF 8D 45 80 6A 64 57 50 89 7D E4 89 7D EC 89 7D F0 89 7D }
    condition:
        all of them
}

rule Windows_Trojan_BloodAlchemy_e510798d {
    meta:
        id = "4n48yt14aEFHpdcpuRZ5pp"
        fingerprint = "v1_sha256_7919bb5f19745a1620e6be91622c40083cbd2ddb02905215736a2ed11e9af5c4"
        version = "1.0"
        date = "2023-09-25"
        modified = "2023-09-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        threat_name = "Windows.Trojan.BloodAlchemy"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 8B EC 83 EC 54 53 8B 5D 08 56 57 33 FF 89 55 F4 89 4D F0 BE 00 00 00 02 89 7D F8 89 7D FC 85 DB }
        $a2 = { 55 8B EC 83 EC 0C 56 57 33 C0 8D 7D F4 AB 8D 4D F4 AB AB E8 42 10 00 00 8B 7D F4 33 F6 85 FF 74 03 8B 77 08 }
    condition:
        any of them
}

rule Windows_Trojan_BloodAlchemy_63084eea {
    meta:
        id = "279qaoadlYQkrKsURzprtR"
        fingerprint = "v1_sha256_3fe64502992281511e942b8f4541d61b33e900dbe23ea9f976c7eb9522ce4cbd"
        version = "1.0"
        date = "2023-09-25"
        modified = "2023-09-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        threat_name = "Windows.Trojan.BloodAlchemy"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 83 EC 38 53 56 57 8B 75 08 8D 7D F0 33 C0 33 DB AB 89 5D C8 89 5D D0 89 5D D4 AB 89 5D }
    condition:
        all of them
}

rule Windows_Trojan_BloodAlchemy_c2d80609 {
    meta:
        id = "4wjuzTI3xoONRrnuZHGCsg"
        fingerprint = "v1_sha256_694a0f917f106fbdde4c8e5dd8f9cdce56e9423ce5a7c3a5bf30bf43308d42e9"
        version = "1.0"
        date = "2023-09-25"
        modified = "2023-09-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        threat_name = "Windows.Trojan.BloodAlchemy"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 83 EC 30 53 56 57 33 C0 8D 7D F0 AB 33 DB 68 02 80 00 00 6A 40 89 5D FC AB AB FF 15 28 }
    condition:
        all of them
}

rule Windows_Trojan_BloodAlchemy_de591c5a {
    meta:
        id = "2qW1m4DjfY0QCWxGptRSUA"
        fingerprint = "v1_sha256_fd5cfe2558a7c02a617003140cdcf477ec451ecea4adf2808bef8f93673c28f1"
        version = "1.0"
        date = "2023-09-25"
        modified = "2023-11-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/disclosing-the-bloodalchemy-backdoor"
        threat_name = "Windows.Trojan.BloodAlchemy"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $crypto_0 = { 32 C7 8A DF 88 04 39 8B C1 6A 05 59 F7 F1 8A C7 8D 4A 01 D2 E3 B1 07 2A CA D2 E8 8B 4D F8 0A D8 02 FB 41 }
        $crypto_1 = { 8A 1F 0F B6 C3 83 E0 7F D3 E0 99 09 55 ?? 0B F0 47 84 DB 79 ?? 83 C1 07 83 F9 3F }
        $crypto_2 = { E8 [4] 03 F0 33 D2 8B C6 89 75 ?? 25 FF FF FF 7F 6A 34 59 F7 F1 8B 45 ?? 66 8B 0C 55 [4] 66 89 0C 43 40 89 45 ?? 3B C7 }
        $crypto_3 = { 61 00 62 00 63 00 64 00 65 00 66 00 67 00 68 00 69 00 6A 00 6B 00 6C 00 6D 00 6E 00 6F 00 70 00 71 00 72 00 73 00 74 00 }
        $com_tm_cid = { 9F 36 87 0F E5 A4 FC 4C BD 3E 73 E6 15 45 72 DD }
        $com_tm_iid = { C0 C7 A4 AB 2F A9 4D 13 40 96 97 20 CC 3F D4 0F 85 }
    condition:
        any of ($crypto_*) and all of ($com_tm_*)
}

