rule Windows_Trojan_Vidar_9007feb2 {
    meta:
        id = "5Njex9Mlciy08WHEw137sj"
        fingerprint = "v1_sha256_fcdef7397f17ee402155e526c6fa8b51f3ea96e203a095b0b4c36cb7d3cc83d1"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { E8 53 FF D6 50 FF D7 8B 45 F0 8D 48 01 8A 10 40 3A D3 75 F9 }
    condition:
        all of them
}

rule Windows_Trojan_Vidar_114258d5 {
    meta:
        id = "6xtTa3fSwINSUvBZqzzCtd"
        fingerprint = "v1_sha256_9ea3ea0533d14edd0332fa688497efd566a890d1507214fc8591a0a11433d060"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "BinanceChainWallet" fullword
        $a2 = "*wallet*.dat" fullword
        $a3 = "SOFTWARE\\monero-project\\monero-core" fullword
        $b1 = "CC\\%s_%s.txt" fullword
        $b2 = "History\\%s_%s.txt" fullword
        $b3 = "Autofill\\%s_%s.txt" fullword
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_Vidar_32fea8da {
    meta:
        id = "3GMFgVZUPHlDR4VznBZ2mV"
        fingerprint = "v1_sha256_1a18cdc3bd533c34eb05b239830ecec418dc76ee9f4fcfc48afc73b07d55b3cd"
        version = "1.0"
        date = "2023-05-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "6f5c24fc5af2085233c96159402cec9128100c221cb6cb0d1c005ced7225e211"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 4F 4B 58 20 57 65 62 33 20 57 61 6C 6C 65 74 }
        $a2 = { 8B E5 5D C3 5E B8 03 00 00 00 5B 8B E5 5D C3 5E B8 08 00 00 }
        $a3 = { 83 79 04 00 8B DE 74 08 8B 19 85 DB 74 62 03 D8 8B 03 85 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Vidar_c374cd85 {
    meta:
        id = "2gsKgc2bcyqmgQmqXKVPNO"
        fingerprint = "v1_sha256_8e183f780400f3bf9840798d53b431a4bf28bc43e07d69a3d614217e02f5dd79"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-10-14"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "1c677585a8b724332849c411ffe2563b2b753fd6699c210f0720352f52a6ab72"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 EC 0C 53 8B 5E 74 39 9E 44 01 00 00 75 07 33 C0 E9 88 00 00 00 57 8B BE E0 00 00 00 85 FF 74 79 8B 8E E4 00 00 00 85 C9 74 6F 8B 86 44 01 00 00 8B D0 03 C7 8D 4C 01 F8 2B D3 89 4D }
    condition:
        all of them
}

rule Windows_Trojan_Vidar_65d3d7e5 {
    meta:
        id = "3ZuYZoXYV6QIWsgb7ZJZa0"
        fingerprint = "v1_sha256_2b340f43faf563c7edbce6323d551208c4d9541d7153ea6c1c0d9a95b351e54b"
        version = "1.0"
        date = "2024-10-14"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Vidar"
        reference_sample = "83d7c2b437a5cbb314c457d3b7737305dadb2bc02d6562a98a8a8994061fe929"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str_1 = "avghooka.dll" wide fullword
        $str_2 = "api_log.dll" wide fullword
        $str_3 = "babyfox.dll" ascii fullword
        $str_4 = "vksaver.dll" ascii fullword
        $str_5 = "delays.tmp" wide fullword
        $str_6 = "\\Monero\\wallet.keys" ascii fullword
        $str_7 = "wallet_path" ascii fullword
        $str_8 = "Hong Lee" ascii fullword
        $str_9 = "milozs" ascii fullword
    condition:
        6 of them
}

