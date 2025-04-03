rule Linux_Trojan_Generic_402be6c5 {
    meta:
        id = "53nBKjuVoZpV7fSm5l0RWG"
        fingerprint = "v1_sha256_b32111972bc21822f0f2c8e47198c90b70e78667410175257b9542c212fc3a1d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "d30a8f5971763831f92d9a6dd4720f52a1638054672a74fdb59357ae1c9e6deb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 52 4C 95 42 11 01 64 E9 D7 39 E4 89 34 FA 48 01 02 C1 3B 39 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5420d3e7 {
    meta:
        id = "5H1Ubrx54Gtsnh1qnpmm5w"
        fingerprint = "v1_sha256_8ba3566ec900e37f05f11d40c65ffe1dfc587c553fa9c28b71ced7a9a90f50c3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "103b8fced0aebd73cb8ba9eff1a55e6b6fa13bb0a099c9234521f298ee8d2f9f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 63 00 5F 5A 4E 34 41 52 43 34 37 65 6E 63 72 79 70 74 45 50 63 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_4f4cc3ea {
    meta:
        id = "1sS78Y7qZSSpu7UMFvNjr2"
        fingerprint = "v1_sha256_9eb0d93b8c1a579ca8362d033edecbbe6a9ade82f6ae5688c183b97ed7b97faa"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "32e25641360dbfd50125c43754cd327cf024f1b3bfd75b617cdf8a17024e2da5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 4A 4E 49 20 55 4E 50 41 43 4B 20 44 45 58 20 53 54 41 52 54 20 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_703a0258 {
    meta:
        id = "1D945f55lsL6eFOy4Txo2Y"
        fingerprint = "v1_sha256_cb37930637b8da91188d199ee20f1b64a0b1f13e966a99e69b983e623dac51de"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b086d0119042fc960fe540c23d0a274dd0fb6f3570607823895c9158d4f75974"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C2 F7 89 76 7E 86 87 F6 2B A3 2C 94 61 36 BE B6 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_378765e4 {
    meta:
        id = "5mNbgNYnCU46qDVbUVNzLp"
        fingerprint = "v1_sha256_dd10305f553fa94ff83fafa84cff3d544f097b617fca20760eef838902e1f7db"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? 22 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_f657fb4f {
    meta:
        id = "6txlp6lasuK2JeqdJg5IHO"
        fingerprint = "v1_sha256_af4fa2c21b47f360b425ebbfea624e3728cd682e54e367d265b4f3a6515b0720"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_be1757ef {
    meta:
        id = "5EGwzLxITLZGH8v7mxfcIt"
        fingerprint = "v1_sha256_567d33c262e5f812c6a702bcc0a1f0cf576b67bf7cf67bb82b5f9ce9f233aaff"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "f3e4e2b5af9d0c72aae83cec57e5c091a95c549f826e8f13559aaf7d300f6e13"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 54 68 75 20 4D 61 72 20 31 20 31 34 3A 34 34 3A 30 38 20 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_7a95ef79 {
    meta:
        id = "7mdLPShRP3IXXktMJVqW0K"
        fingerprint = "v1_sha256_6da43e4bab6b2024b49dfc943f099fb21c06d8d4a082a05594b07cb55989183c"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "f59340a740af8f7f4b96e3ea46d38dbe81f2b776820b6f53b7028119c5db4355"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 1C 8B 54 24 20 8B 74 24 24 CD 80 5E 5A 59 5B C3 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_1c5e42b7 {
    meta:
        id = "58CCJD21MzBoTfWZXQAyOv"
        fingerprint = "v1_sha256_cd759b87a303fafb9461d0a73b6a6b3f468b1f3db0189ba0e584a629e5d78da1"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 FF 75 1C 83 EC 0C 68 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_8ca4b663 {
    meta:
        id = "4TtzJxrdUmkNNRbDAoNbS9"
        fingerprint = "v1_sha256_43b8cae2075f55a98b226f865d54e1c96345db0564815d849b3458d3f3ffee7f"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ddf479e504867dfa27a2f23809e6255089fa0e2e7dcf31b6ce7d08f8d88947e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 28 60 DF F2 FB B7 E7 EB 96 D1 E6 96 88 12 96 EB 8C 94 EB C7 4E }
    condition:
        all of them
}

rule Linux_Trojan_Generic_d3fe3fae {
    meta:
        id = "28PoEVnpGGucFPhxTsLXOz"
        fingerprint = "v1_sha256_0b980a0bcf8340410fe2b53d109f629c6e871ebe82af467153d7b50b73fd8644"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "2a2542142adb05bff753e0652e119c1d49232d61c49134f13192425653332dc3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 47 53 45 54 2C 20 70 69 64 2C 20 4E 54 5F 50 52 53 54 41 54 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5e981634 {
    meta:
        id = "29SlZTxCfUgu9UuzpTJ0QU"
        fingerprint = "v1_sha256_4623c07a15588788ec8a484642a33f2d18127849302d57520a0dac875564f62c"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "448e8d71e335cabf5c4e9e8d2d31e6b52f620dbf408d8cc9a6232a81c051441b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 74 1D 8B 44 24 68 89 84 24 A4 00 00 00 8B 44 24 6C 89 84 24 A8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_d8953ca0 {
    meta:
        id = "3B0RRdiAPTnMFPWP3G5AQk"
        fingerprint = "v1_sha256_cbc1a60a1d9525f7230336dff07f56e6a0b99e7c70c99d3f4363c06ed0071716"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "552753661c3cc7b3a4326721789808482a4591cb662bc813ee50d95f101a3501"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 5B 9C 9C 9C 9C 5C 5D 5E 5F 9C 9C 9C 9C B1 B2 B3 B4 9C 9C 9C 9C }
    condition:
        all of them
}

rule Linux_Trojan_Generic_181054af {
    meta:
        id = "6uaAykH0W0LRLD7BySjX8e"
        fingerprint = "v1_sha256_e92807b603dd33fe7a083985644a213913a77e81c068623fdac7931148207b91"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "e677f1eed0dbb4c680549e0bf86d92b0a28a85c6d571417baaba0d0719da5f93"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6D 6F 64 00 73 65 74 75 74 78 65 6E 74 00 67 6D 74 69 6D 65 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_c3d529a2 {
    meta:
        id = "44VaW2IramqmBWnOK5cP8R"
        fingerprint = "v1_sha256_a508acd95844a4385943166f715606199048d96be0098bc89f9be7b9db34833e"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b46135ae52db6399b680e5c53f891d101228de5cd6c06b6ae115e4a763a5fb22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 1C 31 C0 5B 5E 5F 5D C3 8B 1C 24 C3 8D 64 24 04 53 8B DA 5B }
    condition:
        all of them
}

rule Linux_Trojan_Generic_4675dffa {
    meta:
        id = "7EepklPFp1jBQdSlz1W9r8"
        fingerprint = "v1_sha256_d2865a869d0cf0bf784106fe6242a4c7f58e58a43c4d4ae0241b10569810904d"
        version = "1.0"
        date = "2023-07-28"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "43e14c9713b1ca1f3a7f4bcb57dd3959d3a964be5121eb5aba312de41e2fb7a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = ", i = , not , val ./zzzz.local.onion"
        $a2 = { 61 74 20 20 25 76 3D 25 76 2C 20 28 63 6F 6E 6E 29 20 28 73 63 61 6E 20 20 28 73 63 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5e3bc3b3 {
    meta:
        id = "416ZKKpYacnUrCYz1mqVsS"
        fingerprint = "v1_sha256_33c14a6b8b5a2fc105ea6f1d5ee89e53f6c5e44126b9cf687058de64d649b5ca"
        version = "1.0"
        date = "2024-09-20"
        modified = "2024-11-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Rule for custom Trojan found in Linux REF6138."
        category = "INFO"
        threat_name = "Linux.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $enc1 = { 74 73 0A 1C 1A 54 1A 11 54 0C 18 43 59 5B 3A 11 0B 16 14 10 0C 14 5B }
        $enc2 = { 18 1A 1A 1C 09 0D 43 59 0D 1C 01 0D 56 11 0D 14 15 55 18 09 09 15 10 }
        $enc3 = { 18 1A 1A 1C 09 0D 54 15 18 17 1E 0C 18 1E 1C 43 59 0B 0C }
        $enc4 = { 34 16 03 10 15 15 18 56 4C 57 49 59 51 2E 10 17 1D 16 0E 0A 59 37 }
        $key = "yyyyyyyy"
    condition:
        1 of ($enc*) and $key
}

