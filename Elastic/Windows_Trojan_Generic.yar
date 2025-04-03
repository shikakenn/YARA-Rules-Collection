rule Windows_Trojan_Generic_a681f24a {
    meta:
        id = "cZqrpvQitxx1Td4prr96T"
        fingerprint = "v1_sha256_72bfefc8f92dbe65d197e02bf896315dcbc54d7b68d0434f43de026ccf934f40"
        version = "1.0"
        date = "2021-06-10"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a796f316b1ed7fa809d9ad5e9b25bd780db76001345ea83f5035a33618f927fa"
        severity = 25
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = "_kasssperskdy" wide fullword
        $b = "[Time:]%d-%d-%d %d:%d:%d" wide fullword
        $c = "{SDTB8HQ9-96HV-S78H-Z3GI-J7UCTY784HHC}" wide fullword
    condition:
        2 of them
}

rule Windows_Trojan_Generic_ae824b13 : ref1296 {
    meta:
        id = "66QcTFbgkuaesp150EvjNH"
        fingerprint = "v1_sha256_cee46c1efdaa1815606f932a4f79b316e02c1b481e73c4c2f8b7c72023e8684c"
        version = "1.0"
        date = "2022-02-03"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 31 31 34 2E 31 31 34 2E 31 31 34 2E 31 31 34 }
        $a2 = { 69 6E 66 6F 40 63 69 61 2E 6F 72 67 30 }
        $a3 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 30 2E 30 2E 32 36 36 31 2E 39 34 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
        $a4 = { 75 73 65 72 25 33 64 61 64 6D 69 6E 25 32 36 70 61 73 73 77 6F 72 64 25 33 64 64 65 66 61 75 6C 74 25 34 30 72 6F 6F 74 }
    condition:
        3 of them
}

rule Windows_Trojan_Generic_eb47e754 : ref1296 {
    meta:
        id = "68ZRDpFJYn5TPgvh9WDmez"
        fingerprint = "v1_sha256_1d96e813ed0261bd0d7caca2803ed8d5fe4d77ea00efc9130eef86aa872c4656"
        version = "1.0"
        date = "2022-02-03"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 41 20 61 74 20 4C 20 25 64 }
        $a2 = { 74 63 70 69 70 5F 74 68 72 65 61 64 }
        $a3 = { 32 30 38 2E 36 37 2E 32 32 32 2E 32 32 32 }
        $a4 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 37 2E 30 2E 32 39 38 37 2E 31 33 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
    condition:
        3 of them
}

rule Windows_Trojan_Generic_c7fd8d38 {
    meta:
        id = "4IehufxRIXnralz2MzMkDN"
        fingerprint = "v1_sha256_81c56cd741692a7f2a894c2b8f2676aad47f14221228b9466a2ab0f05d76c623"
        version = "1.0"
        date = "2022-02-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a1702ec12c2bf4a52e11fbdab6156358084ad2c662c8b3691918ef7eabacde96"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "PCREDENTIAL" ascii fullword
        $a2 = "gHotkey" ascii fullword
        $a3 = "EFORMATEX" ascii fullword
        $a4 = "ZLibEx" ascii fullword
        $a5 = "9Root!" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Generic_bbe6c282 {
    meta:
        id = "31ezIxZ6uD4j8rN3gu7XJc"
        fingerprint = "v1_sha256_fe874d69ae71775cf997845c90e731479569e2ac1ac882a4b8c3c73d015b1f30"
        version = "1.0"
        date = "2022-03-02"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 00 D1 1C A5 03 08 08 00 8A 5C 01 08 08 00 8A 58 01 2E 54 FF }
    condition:
        all of them
}

rule Windows_Trojan_Generic_889b1248 {
    meta:
        id = "50xv1fDnYrgDkAotuc1M85"
        fingerprint = "v1_sha256_b3bb93b95377d6c6606d29671395b78c0954cc47d5cc450436799638d0458469"
        version = "1.0"
        date = "2022-03-11"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a48d57a139c7e3efa0c47f8699e2cf6159dc8cdd823b16ce36257eb8c9d14d53"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "BELARUS-VIRUS-MAKER" ascii fullword
        $a2 = "C:\\windows\\temp\\" ascii fullword
        $a3 = "~c~a~n~n~a~b~i~s~~i~s~~n~o~t~~a~~d~r~u~g~" ascii fullword
        $a4 = "untInfector" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Generic_02a87a20 {
    meta:
        id = "5XOmIlMlmBy3wlwrZm1FwX"
        fingerprint = "v1_sha256_610db1b429ed2ecfc552f73ed4782cb56254e6fc98b728ffeff6938fbcce9616"
        version = "1.0"
        date = "2022-03-04"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 24 3C 8B C2 2B C1 83 F8 01 72 3A 8D 41 01 83 FA 08 89 44 24 38 8D 44 }
    condition:
        all of them
}

rule Windows_Trojan_Generic_4fbff084 {
    meta:
        id = "2A5iUeSrtlOYfPeE6QemsF"
        fingerprint = "v1_sha256_47d1a01e0edee3239d99ff1f32eb4cfc77d6e38823fed799a562e142d3d3a22d"
        version = "1.0"
        date = "2023-02-28"
        modified = "2023-04-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Shellcode found in REF2924, belonging to for now unknown trojan"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "7010a69ba77e65e70f4f3f4a10af804e6932c2218ff4abd5f81240026822b401"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $string_decryption = { 8A 44 30 ?? 8A CD 88 45 ?? 32 C5 C0 C1 ?? 88 04 3E 0F B6 C5 0F B6 D9 0F AF D8 0F B6 C1 0F B6 D1 88 6D ?? 0F AF D0 0F B6 C5 0F B6 CD 0F AF C8 8A 6D ?? 8A 45 ?? C0 CB ?? 02 D1 32 DA 02 EB 88 6D ?? 38 45 ?? 74 ?? 8B 45 ?? 46 81 FE ?? ?? ?? ?? 7C ?? }
        $thread_start = { E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? BB ?? ?? ?? ?? 50 6A ?? 5A 8B CF 89 5C 24 ?? E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? }
        $resolve = { 8B 7A ?? 8D 5D ?? 85 FF 74 ?? 0F B7 0F 8D 7F ?? 8D 41 ?? 83 F8 ?? 77 ?? 83 C1 ?? 0F B7 33 83 C3 ?? 8D 46 ?? 83 F8 ?? 77 ?? 83 C6 ?? 85 C9 }
    condition:
        2 of them
}

rule Windows_Trojan_Generic_73ed7375 {
    meta:
        id = "1Ar7HdcwR3ZM7D3gH9Pekc"
        fingerprint = "v1_sha256_7e27c9377d0b2058a2a36da4ac7d37a54c566f3246e69aa356171edae6b478c5"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "2b17328a3ef0e389419c9c86f81db4118cf79640799e5c6fdc97de0fc65ad556"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 8B 03 48 8B CE 49 8D 54 04 02 41 FF D6 48 89 03 48 83 C3 08 48 }
        $a2 = { 41 3C 42 8B BC 08 88 00 00 00 46 8B 54 0F 20 42 8B 5C 0F 24 4D }
    condition:
        all of them
}

rule Windows_Trojan_Generic_96cdf3c4 {
    meta:
        id = "6lxlVcXTBFCBZkGPo0RCcX"
        fingerprint = "v1_sha256_f92e5549aca320d71e1eec8daa82e8bbf3517c7f23f376bb355fdfa32da2e7a9"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "9a4d68de36f1706a3083de7eb41f839d8c7a4b8b585cc767353df12866a48c81"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 74 24 28 48 8B 46 10 48 8B 4E 18 E8 9A CA F8 FF 84 C0 74 27 48 8B 54 }
        $a2 = { F2 74 28 48 89 54 24 18 48 89 D9 48 89 D3 E8 55 40 FF FF 84 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Generic_f0c79978 {
    meta:
        id = "74igaDFINlPOvOo8AkToZY"
        fingerprint = "v1_sha256_b16971ed0947660dda8d79c11531a9498a80e00f2dbc2c0eb63895b7f5c5f980"
        version = "1.0"
        date = "2023-07-27"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "8f800b35bfbc8474f64b76199b846fe56b24a3ffd8c7529b92ff98a450d3bd38"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\IronPython."
        $a2 = "\\helpers\\execassembly_x64"
    condition:
        all of them
}

rule Windows_Trojan_Generic_40899c85 {
    meta:
        id = "3W2Li2xtYsJIta1aLo3khB"
        fingerprint = "v1_sha256_317034add0343baa26548712de8b2acc04946385fbee048cea0bd8d7ae642b36"
        version = "1.0"
        date = "2023-12-15"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "88eb4f2e7085947bfbd03c69573fdca0de4a74bab844f09ecfcf88e358af20cc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "_sqlDataTypeSize"
        $a2 = "ChromeGetName"
        $a3 = "get_os_crypt"
    condition:
        all of them
}

rule Windows_Trojan_Generic_9997489c {
    meta:
        id = "7VatYWmIZQt5PLEuddV8JQ"
        fingerprint = "v1_sha256_857bbf64ced06f76eb50afbfbb699c62e11625196213c2e5267b828cca911b74"
        version = "1.0"
        date = "2024-01-31"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $ldrload_dll = { 43 6A 45 9E }
        $loadlibraryw = { F1 2F 07 B7 }
        $ntallocatevirtualmemory = { EC B8 83 F7 }
        $ntcreatethreadex = { B0 CF 18 AF }
        $ntqueryinformationprocess = { C2 5D DC 8C }
        $ntprotectvirtualmemory = { 88 28 E9 50 }
        $ntreadvirtualmemory = { 03 81 28 A3 }
        $ntwritevirtualmemory = { 92 01 17 C3 }
        $rtladdvectoredexceptionhandler = { 89 6C F0 2D }
        $rtlallocateheap = { 5A 4C E9 3B }
        $rtlqueueworkitem = { 8E 02 92 AE }
        $virtualprotect = { 0D 50 57 E8 }
    condition:
        4 of them
}

rule Windows_Trojan_Generic_2993e5a5 {
    meta:
        id = "5JGHlvGKfYKmUrw7AjSvXQ"
        fingerprint = "v1_sha256_37a10597d1afeb9411f6c652537186628291cbe6af680abe12bb96591add7e78"
        version = "1.0"
        date = "2024-03-18"
        modified = "2024-03-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "9f9b926cef69e879462d9fa914dda8c60a01f3d409b55afb68c3fb94bf1a339b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }
    condition:
        1 of them
}

rule Windows_Trojan_Generic_0e135d58 {
    meta:
        id = "2OeW9YqHd1XrMfX73NV6vq"
        fingerprint = "v1_sha256_bc10218b1d761f72836bb5f9bb41d3f0fe13c4baa1109025269f938ec642aec4"
        version = "1.0"
        date = "2024-03-19"
        modified = "2024-03-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }
    condition:
        1 of them
}

