rule Linux_Trojan_Winnti_61215d98 {
    meta:
        id = "7YV99Dak1TYSSRsoxGbfSH"
        fingerprint = "v1_sha256_051cc157f189094d25d45e66e410bdfd61ed7649a4c935d076cec1597c5debf5"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Winnti"
        reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_4c5a1865 {
    meta:
        id = "KEdKa4lnr5SxxmQ1SchIH"
        fingerprint = "v1_sha256_69f6dcba59ec8cd7f4dfe853495a35601e35d74476fad9e18bef7685a68ece51"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "0d963a713093fc8e5928141f5747640c9b43f3aadc8a5478c949f7ec364b28ad"
        threat_name = "Linux.Trojan.Winnti"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C1 E8 1F 84 C0 75 7B 85 D2 89 D5 7E 75 8B 47 0C 39 C6 7D 6E 44 8D }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_6f4ca425 {
    meta:
        id = "cH7YI8ObKWCswv3nYtBvi"
        fingerprint = "v1_sha256_a1ffc0e3d27c4bb9fd10f14d45b649b4f059c654b31449013ac06d0981ed25ed"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "161af780209aa24845863f7a8120aa982aa811f16ec04bcd797ed165955a09c1"
        threat_name = "Linux.Trojan.Winnti"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 E5 48 89 7D D8 48 8B 45 D8 0F B6 40 27 0F BE C0 89 45 F8 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_de4b0f6e {
    meta:
        id = "3ZpszYIGrcDMuuc4z9qKA7"
        fingerprint = "v1_sha256_fb7b0ff4757dfc1ba2ca8585d5ddf14aae03063e10bdc2565443362c6ba37c30"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "a6b9b3ea19eaddd4d90e58c372c10bbe37dbfced638d167182be2c940e615710"
        threat_name = "Linux.Trojan.Winnti"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 85 30 FF FF FF 02 00 48 8D 85 30 FF FF FF 48 8D 50 02 0F B7 85 28 FF }
    condition:
        all of them
}

