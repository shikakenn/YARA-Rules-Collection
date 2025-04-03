rule Linux_Trojan_Metasploit_69e20012 {
    meta:
        id = "6jM8deyAR9bVjfCxcaZhey"
        fingerprint = "v1_sha256_5d3c3e3ba7d5d0c20d2fa1a53032da9a93a6727dcd6cb3497bb7bfb8272e4f2b"
        version = "1.0"
        date = "2024-05-03"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "debb5d12c1b876f47a0057aad19b897c21f17de7b02c0e42f4cce478970f0120"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $mmap = { 31 FF 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A 6A 07 5A 0F 05 48 85 C0 78 }
        $socket = { 41 59 50 6A 29 58 99 6A 02 5F 6A 01 5E [0-6] 0F 05 48 85 C0 78 }
        $connect = { 51 48 89 E6 6A 10 5A 6A 2A 58 0F 05 59 48 85 C0 79 }
        $failure_handler = { 57 6A 23 58 6A 00 6A 05 48 89 E7 48 31 F6 0F 05 59 59 5F 48 85 C0 79 }
        $exit = { 6A 3C 58 6A 01 5F 0F 05 }
        $receive = { 5A 0F 05 48 85 C0 78 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_0c629849 {
    meta:
        id = "5zLlnlHPzOi910JBwEPuPF"
        fingerprint = "v1_sha256_2bea8f569728ba81af4024bf062a06a5c91b1f057a0b62fe6d51b6fcadedf58c"
        version = "1.0"
        date = "2024-05-03"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "ad070542729f3c80d6a981b351095ab8ac836b89a5c788dff367760a2d8b1dbb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $socket_call = { 6A 29 58 6A 0A 5F 6A 01 5E 31 D2 0F 05 50 5F }
        $populate_sockaddr_in6 = { 99 52 52 52 66 68 }
        $calls = { 6A 31 58 6A 1C 5A 0F 05 6A 32 58 6A 01 5E 0F 05 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 }
        $dup2 = { 48 97 6A 03 5E 6A 21 58 FF CE 0F 05 E0 F7 }
        $exec_call = { 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 54 5F 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_849cc5d5 {
    meta:
        id = "6hIKMix2Dn2d61zekZ642l"
        fingerprint = "v1_sha256_01c708b1e000aecf473e0a1cf23f3812a337b9b21f5b81f7a5e481d06fdaeb16"
        version = "1.0"
        date = "2024-05-03"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "42d734dbd33295bd68e5a545a29303a2104a5a92e5fee31d645e2a6410cc03e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $init1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $init2 = { 6A 10 5A 6A ?? 58 0F }
        $shell1 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
        $shell2 = { 48 96 6A 2B 58 0F 05 50 56 5F 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 97 5F 0F 05 FF E6 }
    condition:
        all of ($init*) and 1 of ($shell*)
}

rule Linux_Trojan_Metasploit_da378432 {
    meta:
        id = "41CaPsQRW2JjSThVyUhVcu"
        fingerprint = "v1_sha256_cd9df6dff23986d61176e4d3440516b0590abdeebef0e456d1f4924724556fe9"
        version = "1.0"
        date = "2024-05-03"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "277499da700e0dbe27269c7cfb1fc385313c4483912a9a3f0c15adba33ecd0bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $str2 = { 6A 10 5A 6A ?? 58 0F }
        $str3 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_b957e45d {
    meta:
        id = "2d1dV7vKUgFDPVFrdnxOxl"
        fingerprint = "v1_sha256_27281303d007e6723308e88f335f52723b3ff0ef733d1a0712f5ba268e53a073"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom nonx TCP reverse shells"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "78af84bad4934283024f4bf72dfbf9cc081d2b92a9de32cc36e1289131c783ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 31 DB 53 43 53 6A 02 6A 66 58 89 E1 CD 80 97 5B }
        $str2 = { 66 53 89 E1 6A 66 58 50 51 57 89 E1 43 CD 80 5B 99 B6 0C B0 03 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_1a98f2e2 {
    meta:
        id = "1irHJgC9U17IeJSfhxJJSH"
        fingerprint = "v1_sha256_23ea1c255472a67746b470e50d982bc91d22ede5e2582cf5cfaa90a1ed4e8805"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom nonx TCP bind shells"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "89be4507c9c24c4ec9a7282f197a9a6819e696d2832df81f7e544095d048fc22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 31 DB 53 43 53 6A 02 6A 66 58 99 89 E1 CD 80 96 43 52 }
        $str2 = { 66 53 89 E1 6A 66 58 50 51 56 89 E1 CD 80 B0 66 D1 E3 CD 80 52 52 56 43 89 E1 B0 66 CD 80 93 B6 0C B0 03 CD 80 89 DF }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_d74153f6 {
    meta:
        id = "10Xo8jPaBJ4bkQ8KrZOa4r"
        fingerprint = "v1_sha256_c60e7e63183f5bf0354a03f8399576e494e44a30257339ebccb6c19e954d6f3a"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom IPv6 TCP reverse shells"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "2823d27492e2e7a95b67a08cb269eb6f4175451d58b098ae429330913397d40a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 31 DB 53 43 53 6A 0A 89 E1 6A 66 58 CD 80 96 99 }
        $str2 = { 89 E1 6A 1C 51 56 89 E1 43 43 6A 66 58 CD 80 89 F3 B6 0C B0 03 CD 80 89 DF }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_f7a31e87 {
    meta:
        id = "1iqSG2zeW24C5Ae8VADzXM"
        fingerprint = "v1_sha256_49583ba4f2bedb9337a8c10df4246bb76a3e60b08ba1a6b8684537fee985d911"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom shell find tag payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "82b55d8c0f0175d02399aaf88ad9e92e2e37ef27d52c7f71271f3516ba884847"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $setup = { 31 DB 53 89 E6 6A 40 B7 0A 53 56 53 89 E1 86 FB 66 FF 01 6A 66 58 CD 80 81 3E }
        $payload1 = { 5F FC AD FF }
        $payload2 = { 5F 89 FB 6A 02 59 6A 3F 58 CD 80 49 79 ?? 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80 }
    condition:
        $setup and 1 of ($payload*)
}

rule Linux_Trojan_Metasploit_b0d2d4a4 {
    meta:
        id = "4FAnH5uXssR5uiUO7PewB3"
        fingerprint = "v1_sha256_bcabf74900222074ecf9051b6e0cb4ca7a240acd047a1b27137d1d198e23f161"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom shell find port payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "a37c888875e84069763303476f0df6769df6015b33aded59fc1e23eb604f2163"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 31 DB 53 89 E7 6A 10 54 57 53 89 E1 B3 07 FF 01 6A 66 58 CD 80 }
        $str2 = { 5B 6A 02 59 B0 3F CD 80 49 }
        $str3 = { 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 99 B0 0B CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_5d26689f {
    meta:
        id = "1MLCq1HmJHHt0g6d3PdKMy"
        fingerprint = "v1_sha256_e7906273aa7f42920be9d06cdae89c81e0a99e532cdcd7bd714acc5f2bbb0ed5"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom bind TCP random port payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "dafefb4d79d848384442a697b1316d93fef2741fca854be744896ce1d7f82073"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $tiny_bind = { 31 D2 52 68 2F 2F 73 68 68 2F 62 69 6E 68 2D 6C 65 2F 89 E7 52 68 2F 2F 6E 63 68 2F 62 69 6E 89 E3 52 57 53 89 E1 31 C0 B0 0B CD 80 }
        $reg_bind_setup = { 31 DB F7 E3 B0 66 43 52 53 6A 02 89 E1 CD 80 52 50 89 E1 B0 66 B3 04 CD 80 B0 66 43 CD 80 59 93 }
        $reg_bind_dup_loop = { 6A 3F 58 CD 80 49 79 }
        $reg_bind_execve = { B0 0B 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 41 CD 80 }
    condition:
        ($tiny_bind) or (all of ($reg_bind*))
}

rule Linux_Trojan_Metasploit_1c8c98ae {
    meta:
        id = "41C9bXHJJ27GpAGqL5m8mS"
        fingerprint = "v1_sha256_fc32aa29f58478f0b7f4f5be61aadec65842c05b7d8ded840530503eae28b8eb"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom add user payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "1a2c40531584ed485f3ff532f4269241a76ff171956d03e4f0d3f9c950f186d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 31 C9 89 CB 6A 46 58 CD 80 6A 05 58 31 C9 51 68 73 73 77 64 68 2F 2F 70 61 68 2F 65 74 63 89 E3 41 B5 04 CD 80 93 }
        $str2 = { 59 8B 51 FC 6A 04 58 CD 80 6A 01 58 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_47f4b334 {
    meta:
        id = "VklZ8hLJfdziWMByUAjB6"
        fingerprint = "v1_sha256_34c8182d3b5ecbebd122d2d58fc0502a6bbca020b528ffdcc9ee988f21512d99"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom exec payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "c3821f63a7ec8861a6168b4bb494bf8cbac436b3abf5eaffbc6907fd68ebedb8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $payload1 = { 31 C9 F7 E1 B0 0B [0-1] 68 2F ?? ?? ?? 68 2F 62 69 6E 89 E3 CD 80 }
        $payload2a = { 31 DB F7 E3 B0 0B 52 }
        $payload2b = { 88 14 1E 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 56 57 53 89 E1 CD 80 }
        $payload3a = { 6A 0B 58 99 52 }
        $payload3b = { 89 E7 68 2F 73 68 00 68 2F 62 69 6E 89 E3 52 E8 }
        $payload3c = { 57 53 89 E1 CD 80 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_0b014e0e {
    meta:
        id = "54A5i2qvZK9eqscs9FkdQ"
        fingerprint = "v1_sha256_cb19a0461d5fe6066d1fed4898ea12a9818be69d870e511559b19d5c7c959819"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x64 msfvenom exec payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "a24443331508cc72b3391353f91cd009cafcc223ac5939eab12faf57447e3162"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $payload1 = { 48 B8 2F [0-1] 62 69 6E 2F 73 68 ?? ?? 50 54 5F 52 5E 6A 3B 58 0F 05 }
        $payload2a = { 48 B8 2F 2F 62 69 6E 2F 73 68 99 EB ?? 5D 52 5B }
        $payload2b = { 54 5E 52 50 54 5F 52 55 56 57 54 5E 6A 3B 58 0F 05 }
        $payload3a = { 48 B8 2F 62 69 6E 2F 73 68 00 99 50 54 5F 52 }
        $payload3b = { 54 5E 52 E8 }
        $payload3c = { 56 57 54 5E 6A 3B 58 0F 05 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_ccc99be1 {
    meta:
        id = "13sgjMmD4ypqybQVShIBT2"
        fingerprint = "v1_sha256_96af2123251587ece32e424202ff61cfa70faf2916cacddf5fcd9d81bf483032"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x64 msfvenom pingback bind shell payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "0e9f52d7aa6bff33bfbdba6513d402db3913d4036a5e1c1c83f4ccd5cc8107c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 56 50 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 85 C0 }
        $str2 = { 51 48 89 E6 54 5E 6A 31 58 6A 10 5A 0F 05 6A 32 58 6A 01 5E 0F 05 }
        $str3 = { 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 48 97 }
        $str4 = { 5E 48 31 C0 48 FF C0 0F 05 6A 3C 58 6A 01 5F 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_ed4b2c85 {
    meta:
        id = "6Joyw1DyKhkYV6WuzlHbQV"
        fingerprint = "v1_sha256_79e466b2f40a6769db498cc28cb22ba72ec20f92c8450d6f1f8301d00012f967"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x64 msfvenom bind TCP random port payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "0709a60149ca110f6e016a257f9ac35c6f64f50cfbd71075c4ca8bfe843c3211"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str = { 6A 29 58 99 6A 01 5E 6A 02 5F 0F 05 97 B0 32 0F 05 96 B0 2B 0F 05 97 96 FF CE 6A 21 58 0F 05 75 ?? 52 48 BF 2F 2F 62 69 6E 2F 73 68 57 54 5F B0 3B 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_2b0ad6f0 {
    meta:
        id = "60lawvPKIuYaYmIWOJtJjw"
        fingerprint = "v1_sha256_91b4547e44c40cafe09dd415f0b5dfe5980fcb10d50aeae844cf21e7608d9a9d"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x64 msfvenom find TCP port payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "aa2bce61511c72ac03562b5178aad57bce8b46916160689ed07693790cbfbeec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 48 31 FF 48 31 DB B3 18 48 29 DC 48 8D 14 24 48 C7 02 10 00 00 00 48 8D 74 24 08 6A 34 58 0F 05 48 FF C7 }
        $str2 = { 48 FF CF 6A 02 5E 6A 21 58 0F 05 48 FF CE 79 }
        $str3 = { 48 89 F3 BB 41 2F 73 68 B8 2F 62 69 6E 48 C1 EB 08 48 C1 E3 20 48 09 D8 50 48 89 E7 48 31 F6 48 89 F2 6A 3B 58 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_bf205d5a {
    meta:
        id = "64VhwDMZMrK3XCPQ59R4wC"
        fingerprint = "v1_sha256_9f4c84fadc3d7555c80efc9c9c5dcb01d4ea65d2ff191aa63ae8316f763ded3f"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom bind IPv6 TCP shell payloads "
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "2162a89f70edd7a7f93f8972c6a13782fb466cdada41f255f0511730ec20d037"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 6A 7D 58 99 B2 07 B9 00 10 00 00 89 E3 66 81 E3 00 F0 CD 80 31 DB F7 E3 53 43 53 6A ?? 89 E1 B0 66 CD 80 }
        $str2 = { 51 6A 04 54 6A 02 6A 01 50 }
        $str3 = { 6A 0E 5B 6A 66 58 CD 80 89 F8 83 C4 14 59 5B 5E }
        $str4 = { CD 80 93 B6 0C B0 03 CD 80 87 DF 5B B0 06 CD 80 }
        $ipv6 = { 6A 02 5B 52 52 52 52 52 52 ?? ?? ?? ?? ?? 89 E1 6A 1C }
        $socket = { 51 50 89 E1 6A 66 58 CD 80 D1 E3 B0 66 CD 80 57 43 B0 66 89 51 04 CD 80 }
    condition:
        3 of ($str*) and $ipv6 and $socket
}

rule Linux_Trojan_Metasploit_e5b61173 {
    meta:
        id = "668jqNXyPWDRLqJ23imOH1"
        fingerprint = "v1_sha256_f60d2de0b7fac06b62616d7c7f51e9374df3895eb30a07040e742cbcb462a418"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom stageless TCP reverse shell payload"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "8032a7a320102c8e038db16d51b8615ee49f04dab1444326463f75ce0c5947a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 93 59 B0 3F CD 80 49 79 }
        $str2 = { 89 E1 B0 66 50 51 53 B3 03 89 E1 CD 80 52 }
        $str3 = { 89 E3 52 53 89 E1 B0 0B CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_dd5fd075 {
    meta:
        id = "2Wg1uXQRAnfeHHxwXWuiEa"
        fingerprint = "v1_sha256_f5101d5ddb1a84127e755677da70d9154849c546ac6ef0e7ef2639c82911eb92"
        version = "1.0"
        date = "2024-05-07"
        modified = "2024-05-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detects x86 msfvenom TCP bind shell payloads"
        category = "INFO"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "b47132a92b66c32c88f39fe36d0287c6b864043273939116225235d4c5b4043a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 5B 5E 52 }
        $str2 = { 6A 10 51 50 89 E1 6A 66 58 CD 80 89 41 04 B3 04 B0 66 CD 80 43 B0 66 CD 80 93 59 }
        $str3 = { 6A 3F 58 CD 80 49 79 F8 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 B0 0B CD 80 }
    condition:
        all of them
}

