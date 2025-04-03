rule Linux_Trojan_Xorddos_2aef46a6 {
    meta:
        id = "1cVNukRN3JssjxsSPo1XwE"
        fingerprint = "v1_sha256_d2c88774eb5227cf2d133644c648ebe5ba40c7e0acb2b432bc6a1a9da10bfb3f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 25 64 2D 2D 25 73 5F 25 64 3A 25 73 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_a6572d63 {
    meta:
        id = "19PN3R6luhcuwAIpSgKPl9"
        fingerprint = "v1_sha256_237392fe51c8528cb5ed446facfcd3535b8e1d594d77a542361873bd52426fa7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2ff33adb421a166895c3816d506a63dff4e1e8fa91f2ac8fb763dc6e8df59d6e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C8 0F B6 46 04 0F B6 56 05 C1 E0 08 09 D0 89 45 CC 0F B6 46 06 0F B6 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e41143e1 {
    meta:
        id = "1fGUcDV2zykgkKA0BYS2uz"
        fingerprint = "v1_sha256_4564bf2019ff5086071ff147c9cf1e16b8627ce5d70cbe8370aecbd518d94b57"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 73 1E 80 3C 06 00 8D 14 30 8D 4C 37 FF 74 0D EB 36 0F B6 42 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_0eb147ca {
    meta:
        id = "5A0Wjd43ibYOGPxNXsYU7C"
        fingerprint = "v1_sha256_b20479af0767e5e8579489b5298648b9cc84b3e0778f58d8dc9deb252d0f4806"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 83 45 F0 01 8B 45 F0 89 45 E8 8B 45 E8 83 C4 18 5F 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ba961ed2 {
    meta:
        id = "3c79aOmheOZMdD5lMmEMKP"
        fingerprint = "v1_sha256_5b486c698c9c61dc126be5dbeea862b1f9bb5a6859c02a0fff125a9890147a6b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 C9 C3 55 89 E5 83 EC 38 C7 45 F8 FF FF FF FF C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2084099a {
    meta:
        id = "6Wx9MIHsb6paWpFzMxq5rx"
        fingerprint = "v1_sha256_6674be1438ec290550c9586afda335755279a4aedadde455ffc0b41d1a0e634d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 8B 45 FC 8B 50 18 8B 45 08 89 50 18 8B 45 FC 8B 40 08 85 C0 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_61c88137 {
    meta:
        id = "1ESIRfccPZPhIQKT5RCVWr"
        fingerprint = "v1_sha256_e999355606ee7389be160ce3e96c6a62d7f9132b95cfec7d9f8b1a670551e6b8"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "479ef38fa00bb13a3aa8448aa4a4434613c6729975e193eec29fc5047f339111"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 8B C1 8B 0C 24 8D 64 24 FC 89 0C 24 8B 4D E8 87 0C 24 96 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_debb98a1 {
    meta:
        id = "7CcbQt3kJySQVeVHKdWCHg"
        fingerprint = "v1_sha256_c2e43818fcf18d34a6a3611aaaafde31d96b41867d15dfdb1dec20203f5907eb"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "494f549e3dd144e8bcb230dd7b3faa8ff5107d86d9548b21b619a0318e362cad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F4 87 5D F4 5B 9C 51 8B 4C 24 04 8D 49 2A 87 4C 24 04 89 4C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1d6e10fd {
    meta:
        id = "4jElrAYUW3WBtXNCh9j2sR"
        fingerprint = "v1_sha256_01ec1af1ca03173e867113c3bec7911990a0c8c2d9f19b5233715a7f7490f5f1"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "4c7851316f01ae84ee64165be3ba910ab9b415d7f0e2f5b7e5c5a0eaefa3c287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 04 9C 83 C5 7B 9D 8D 6D 85 87 54 24 00 9C 83 C5 26 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e3ffbbcc {
    meta:
        id = "3cRSC97PzgBEGDhzYnkhLk"
        fingerprint = "v1_sha256_54711c2d3e6d73cf4358ba4a65cb19d996adcfa905c0089a18a61fe841fe9a34"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "28b7ddf2548411910af033b41982cdc74efd8a6ef059a54fda1b6cbd59faa8f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF 10 52 FB FF D0 52 FB FF 00 52 FB FF D0 52 FB FF F0 51 FB }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_30f3b4d4 {
    meta:
        id = "5pCUiWABqXD23YTGPS9RR3"
        fingerprint = "v1_sha256_99efc257ff2afb779304451bd9f6f6ce9e88f54954189601ed10e95e2268dd4f"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "5b15d43d3535965ec9b84334cf9def0e8c3d064ffc022f6890320cd6045175bc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 70 9C 83 C5 17 9D 8D 6D E9 0F 10 74 24 60 8B F6 0F 10 6C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ca75589c {
    meta:
        id = "5IDQVxiznMeaCTeUAqbRpD"
        fingerprint = "v1_sha256_c717e6f85a5b30514803ba43c85d82e2aaa4533b7f74db5345df83d1cc4c6551"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0448c1b2c7c738404ba11ff4b38cdc8f865ccf1e202f6711345da53ce46e7e16"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6D E0 25 01 00 00 00 55 8B EC C9 87 D1 87 0C 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_7909cdd2 {
    meta:
        id = "2bxQW9gWn7GQVKtG7vt2p4"
        fingerprint = "v1_sha256_4b2557ab78d22ae4f46e5813ba5dc4663cd92b945a1add3155f77d3030ccc92d"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0a4a5874f43adbe71da88dc0ef124f1bf2f4e70d0b1b5461b2788587445f79d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { A5 07 00 EC C5 19 08 EC C5 19 08 18 06 00 00 18 06 00 00 06 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2522d611 {
    meta:
        id = "4X9uMZAP1yWziu7sToC8PN"
        fingerprint = "v1_sha256_59f2552809bc48e16719cb9b4d2a7b99999307803fce031ca39eb24e14b88908"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0c2be53e298c285db8b028f563e97bf1cdced0c4564a34e740289b340db2aac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 04 57 8B 7C 24 02 5F 87 44 24 00 50 8B 44 24 04 8D 40 42 87 44 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_56bd04d3 {
    meta:
        id = "1tic2z7Nt5uDVM2ggY2yFM"
        fingerprint = "v1_sha256_47a33fcd69dd78cbc6c3274aeaa8dddabe119ae65b59077e1807657b8a67fed3"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0d2ce3891851808fb36779a348a83bf4aa9de1a2b2684fd0692434682afac5ec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 5C 87 5C 24 04 89 5C 24 04 8B 1C 24 8D 64 24 04 8B 00 8B F6 87 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_f412e4b4 {
    meta:
        id = "6shlRVqvnz8aVOedd1BrqX"
        fingerprint = "v1_sha256_b4e1b193e80aa88b91255df3a5f2e45de7f23fdba4a28d3ceb12db63098e70e5"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0e3a3f7973f747fcb23c72289116659c7f158c604d937d6ca7302fbab71851e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 04 C1 E2 05 8B C0 03 C2 9C 83 C5 0F 9D 8D 6D F1 05 0C 00 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_71f8e26c {
    meta:
        id = "5t1Yjehm86BGcRQdhcihpu"
        fingerprint = "v1_sha256_f9f2f22acd4f52cc313e3ecf425604651e0b8c78e33480d4d05bae5b8c9661fb"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "13f873f83b84a0d38eb3437102f174f24a0ad3c5a53b83f0ee51c62c29fb1465"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 8D 64 24 04 1B 07 87 DA 8B 5D F4 52 87 DA 5B 83 C2 03 52 8B 54 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1a562d3b {
    meta:
        id = "2LGUMG2jGboUGuId3w5Apy"
        fingerprint = "v1_sha256_8d3b369bdcecd675f99cedf26dba202256555be0f5feae612404f9b5e109fa93"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15731db615b32c49c34f41fe84944eeaf2fc79dafaaa9ad6bf1b07d26482f055"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F0 87 1C 24 91 8D 64 24 FC 89 0C 24 8B C8 8B 04 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_410256ac {
    meta:
        id = "5FD2EpKZE2ZiMz5qPkuRRc"
        fingerprint = "v1_sha256_88227af6d2f365b761961bdf4b94bed81bca79e23d546e69900faa17c3e4dc71"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15f44e10ece90dec1a6104d5be1effefa17614d9f0cfb2784305dab85367b741"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 04 87 CA 8B 4D 0C 52 87 CA 59 03 D1 55 8B EC C9 6A 08 F7 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_93fa87f1 {
    meta:
        id = "5S4LGkQ0qPcxDFNMgBsr7i"
        fingerprint = "v1_sha256_2a1e797d4dd2599b5c67e73e3c909a1803e604edf0b6ba228713ee375ccc9b16"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "165b4a28fd6335d4e4dfefb6c40f41f16d8c7d9ab0941ccd23e36cda931f715e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 03 87 44 24 04 89 44 24 04 8B 04 24 8D 64 24 04 8B 00 9C 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_8677dca3 {
    meta:
        id = "1wmKcy9QQqIjBUa6V5ynuK"
        fingerprint = "v1_sha256_9902758dfb61e8b60b281f3f51cda8a10d58eb0cc20743f97998d7bcf120c299"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "23813dc4aa56683e1426e5823adc3aab854469c9c0f3ec1a3fad40fa906929f2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F2 5E 83 C2 03 8B FF C1 E2 05 9C 83 C5 69 9D 8D 6D 97 03 C2 56 8B 74 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ebce4304 {
    meta:
        id = "4MlNzfFllvlOPE9EgXzzAS"
        fingerprint = "v1_sha256_42fbfc2c2636c2e3a5da5e51c6bf99f6114ec7d00b88371a34e1fdbe81d1264a"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 8D 64 24 04 87 54 24 00 56 8B 74 24 04 5E 9D 9C 83 C5 1E 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_073e6161 {
    meta:
        id = "O6p5v00iWlOFSCeI1zWPr"
        fingerprint = "v1_sha256_2c98058add77c55ab68491eec041d7670f726a9ec93258ae7bb8f0e6721b4ca3"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F9 83 F8 1F 77 33 80 BC 35 B9 FF FF FF 63 76 29 8B 44 24 14 40 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_bef22375 {
    meta:
        id = "5QdGQZNJQSrWPCu47Xt3el"
        fingerprint = "v1_sha256_3991ebdb310338516d5fdd137ba2ac63dc870337785a31d59dcad49135f190e5"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "f47baf48deb71910716beab9da1b1e24dc6de9575963e238735b6bcedfe73122"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C5 35 9D 8D 6D CB 8B 12 9C 83 C5 17 9D 8D 6D E9 6A 04 F7 14 24 FF }
    condition:
        all of them
}

