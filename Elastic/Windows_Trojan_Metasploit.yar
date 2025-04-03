rule Windows_Trojan_Metasploit_a6e956c9 {
    meta:
        id = "2DWOBpkuFTNtmnNAjAD37E"
        fingerprint = "v1_sha256_fb4e3e54618075d5ef6ec98d1ba9c332ce9f677f0879e07b34a2ca08b2180dd9"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies the API address lookup function leverage by metasploit shellcode"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF AC 3C 61 7C 02 2C 20 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_38b8ceec {
    meta:
        id = "2Ymjt53lRcwF3zn3XYycqT"
        fingerprint = "v1_sha256_8e3bc02661cedb9885467373f8120542bb7fc8b0944803bc01642fbc8426298b"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies the API address lookup function used by metasploit. Also used by other tools (like beacon)."
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 85
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_7bc0f998 {
    meta:
        id = "59qKKds51RFjq6xRK3Nk8G"
        fingerprint = "v1_sha256_29cb48086dbcd48bd83c5042ed78370e127e1ea5170ee7383b88659b31e896b5"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies the API address lookup function leverage by metasploit shellcode"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 84
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0 AC 3C 61 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_f7f826b4 {
    meta:
        id = "7HxAKeH3hlRTZIevKp1SLx"
        fingerprint = "v1_sha256_2f5264e07c65d5ef4efe49a48c24ccef9a4b9379db581d2cf18e1131982e6f2f"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies metasploit kernel->user shellcode. Likely used in ETERNALBLUE and BlueKeep exploits."
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 92 31 C9 51 51 49 89 C9 4C 8D 05 0? 00 00 00 89 CA 48 83 EC 20 FF D0 48 83 C4 30 C3 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_24338919 {
    meta:
        id = "2Ig1zPcys3jNtxVA2GgQKp"
        fingerprint = "v1_sha256_af8cceebdebca863019860afca5d7c6400b68c8450bc17b7d7b74aeab2d62d16"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies metasploit wininet reverse shellcode. Also used by other tools (like beacon)."
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 80
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
    condition:
        $a1
}

rule Windows_Trojan_Metasploit_0f5a852d {
    meta:
        id = "6y38camerDeyw3dkwgFRn3"
        fingerprint = "v1_sha256_11cddf2191a2f70222a0c8c591e387b4b5667bc432a2f686629def9252361c1d"
        version = "1.0"
        date = "2021-04-07"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies 64 bit metasploit wininet reverse shellcode. May also be used by other malware families."
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 80
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_c9773203 {
    meta:
        id = "Mj5sWBpT4zs8VGg8mQf5O"
        fingerprint = "v1_sha256_1d6503ccf05b8e8b4368ed0fb2e57aa2be94151ce7e2445b5face7b226a118e9"
        version = "1.0"
        date = "2021-04-07"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies the 64 bit API hashing function used by Metasploit. This has been re-used by many other malware families."
        category = "INFO"
        reference = "https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/block/block_api.asm"
        threat_name = "Windows.Trojan.Metasploit"
        severity = 10
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 4C 03 4C 24 08 45 39 D1 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_dd5ce989 {
    meta:
        id = "5XpZyG7Oewi7AXHlrgJtuO"
        fingerprint = "v1_sha256_5c094979be1cd347ffee944816b819b6fbb62804b183a6120cd3a93d2759155b"
        version = "1.0"
        date = "2021-04-14"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Meterpreter DLL used by Metasploit"
        category = "INFO"
        reference = "https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "86cf98bf854b01a55e3f306597437900e11d429ac6b7781e090eeda3a5acb360"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "metsrv.x64.dll" fullword
        $a2 = "metsrv.dll" fullword
        $b1 = "ReflectiveLoader"
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_Metasploit_96233b6b {
    meta:
        id = "2vnRNF48XqiMEOO9j3Izuc"
        fingerprint = "v1_sha256_09a2b9414a126367df65322966b671fe7ea963cd65ef48e316c9d139ee502d31"
        version = "1.0"
        date = "2021-06-10"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies another 64 bit API hashing function used by Metasploit."
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "e7a2d966deea3a2df6ce1aeafa8c2caa753824215a8368e0a96b394fb46b753b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 31 FF 0F B7 4A 26 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_4a1c4da8 {
    meta:
        id = "2Q8uLwh6HKUv9PvAHbHHnT"
        fingerprint = "v1_sha256_9d3a3164ed1019dcb557cf20734a81be9964a555ddb2e0104f7202880b2ed177"
        version = "1.0"
        date = "2021-06-10"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Metasploit 64 bit reverse tcp shellcode."
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "9582d37ed9de522472abe615dedef69282a40cfd58185813c1215249c24bbf22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 6A 10 56 57 68 99 A5 74 61 FF D5 85 C0 74 0A FF 4E 08 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_91bc5d7d {
    meta:
        id = "50IJOXxaqdiGhGJVedvRg4"
        fingerprint = "v1_sha256_74154902b03c36a4ee9bc54ae9399bae9e6afb7fe8d0fe232b88250afc368d6f"
        version = "1.0"
        date = "2021-08-02"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "0dd993ff3917dc56ef02324375165f0d66506c5a9b9548eda57c58e041030987"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 49 BE 77 73 32 5F 33 32 00 00 41 56 49 89 E6 48 81 EC A0 01 00 00 49 89 E5 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_a91a6571 {
    meta:
        id = "4aprqEIlnqtnmE5tIC69r2"
        fingerprint = "v1_sha256_cc59320ba9f8907d1d9b9dc120d8b4807b419e49c55be1fd5d2cdbb0c5d4e5cc"
        version = "1.0"
        date = "2022-06-08"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "ff7795edff95a45b15b03d698cbdf70c19bc452daf4e2d5e86b2bbac55494472"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 56 65 48 8B 52 60 48 8B 52 18 48 8B 52 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_b29fe355 {
    meta:
        id = "6LiFoqvb6xervp0Mb4mHUJ"
        fingerprint = "v1_sha256_7a2189b59175acb66a7497c692a43c413a476f5c4371f797bf03a8ddb550992c"
        version = "1.0"
        date = "2022-06-08"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "4f0ab4e42e6c10bc9e4a699d8d8819b04c17ed1917047f770dc6980a0a378a68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%04x-%04x:%s" fullword
        $a2 = "\\\\%s\\pipe\\%s" fullword
        $a3 = "PACKET TRANSMIT" fullword
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_66140f58 {
    meta:
        id = "33utqmIMhfBr1P3ZbIIqWA"
        fingerprint = "v1_sha256_0a855b7296f7cea39cc5d57b239d3906133ea43a0811ec60e4d91765cf89aced"
        version = "1.0"
        date = "2022-08-15"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "01a0c5630fbbfc7043d21a789440fa9dadc6e4f79640b370f1a21c6ebf6a710a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_2092c42a {
    meta:
        id = "6T8ugSOQugzSJY27BSds65"
        fingerprint = "v1_sha256_83c46c6b957f10d406ea9985c518eb2fba3e82b9023bfdefa8bdd4be7fb67826"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "e47d88c11a89dcc84257841de0c9f1ec388698006f55a0e15567354b33f07d3c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 65 6E 61 62 6C 65 5F 6B 65 79 62 6F 61 72 64 5F 69 6E 70 75 74 }
        $a2 = { 01 04 10 49 83 C2 02 4D 85 C9 75 9C 41 8B 43 04 4C 03 D8 48 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_46e1c247 {
    meta:
        id = "79NuXbXwnKtCSmx53goDwG"
        fingerprint = "v1_sha256_760a4e28e312a7d744208dc833ffad8d139ce7c536b407625a7fb0dff5ddb1d1"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "ef70e1faa3b1f40d92b0a161c96e13c96c43ec6651e7c87ee3977ed07b950bab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 73 74 64 61 70 69 5F 66 73 5F 66 69 6C 65 }
        $a2 = { 85 D2 74 0E 8B F3 2B 75 F8 8A 01 88 04 0E 41 4A 75 F7 0F B7 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_b62aac1e {
    meta:
        id = "2BzWcXZ4Es6HsIAH1xqzQn"
        fingerprint = "v1_sha256_3ef6b7fb258b060ae00b060dbf9b07620f8cda0d9a827985bbb3ed9617969ef6"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "af9af81f7e46217330b447900f80c9ce38171655becb3b63e51f913b95c71e70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 42 3C 8B AC 10 88 00 00 00 44 8B 54 15 20 44 8B 5C 15 24 4C }
        $a2 = { CB 4D 85 D2 74 10 41 8A 00 4D 03 C3 88 02 49 03 D3 4D 2B D3 }
    condition:
        all of them
}

rule Windows_Trojan_Metasploit_47f5d54a {
    meta:
        id = "1X36mrjTaBQ4dFDujIWjH7"
        fingerprint = "v1_sha256_be080d0aae457348c4a02c204507a8cb14d1728d1bc50d7cf12b577aa06daf9f"
        version = "1.0"
        date = "2023-11-13"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Metasploit"
        reference_sample = "bc3754cf4a04491a7ad7a75f69dd3bb2ddf0d8592ce078b740d7c9c7bc85a7e1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a32 = { 89 45 F8 FF 15 [11] 8B D8 85 DB 74 76 6A 00 6A 04 6A 00 FF 35 [4] 6A 00 6A 00 FF 15 }
        $a64 = { 48 89 7C 24 48 FF 15 [4] 33 D2 44 8B C0 B9 40 00 10 00 FF 15 [4] 48 8B F8 48 85 C0 74 55 48 8B 15 [10] 4C 8B C0 48 8B CB 48 C7 44 24 20 }
    condition:
        any of them
}

