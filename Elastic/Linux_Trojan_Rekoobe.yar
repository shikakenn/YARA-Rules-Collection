rule Linux_Trojan_Rekoobe_e75472fa {
    meta:
        id = "2W6RjHtwvIBRlspNUw28W8"
        fingerprint = "v1_sha256_e3e9934ee8ce6933f676949c5b5c82ad044ac32f08fe86697b0a0cf7fb63fc5e"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "8d2a9e363752839a09001a9e3044ab7919daffd9d9aee42d936bc97394164a88"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 83 F8 01 74 1F 89 D0 48 8B 4C 24 08 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_52462fe8 {
    meta:
        id = "7PwWdvsxUMO65qKKTfECpP"
        fingerprint = "v1_sha256_1ab6979392eeaa7bd6bd84f8d3531bd9071c54b58306a42dcfdd27bf7ec8f8cd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "c1d8c64105caecbd90c6e19cf89301a4dc091c44ab108e780bdc8791a94caaad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 1C D8 48 8B 5A E8 4A 33 0C DE 48 89 4A E0 89 D9 C1 E9 18 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_de9e7bdf {
    meta:
        id = "4NpYTvzCiVnKebfJI3GF8Z"
        fingerprint = "v1_sha256_bdc4a3e4eeffc0d32e6a86dda54beceab8301d0065731d9ade390392ab4c6126"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "447da7bee72c98c2202f1919561543e54ec1b9b67bd67e639b9fb6e42172d951"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F5 48 89 D6 48 C1 EE 18 40 0F B6 F6 48 33 2C F1 48 89 D6 48 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_b41f70c2 {
    meta:
        id = "3eVvIpv8jSsXdfn89Ndab2"
        fingerprint = "v1_sha256_02de55c537da1cc03af26a171c768ad87984e45983c3739f90ad9983c70e7ccf"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "19c1a54279be1710724fc75a112741575936fe70379d166effc557420da714cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E2 10 4D 31 D1 0F B6 D6 48 8B 14 D1 48 C1 E2 08 4C 31 CA 48 89 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_1d307d7c {
    meta:
        id = "7aAOc9zeTGvWq2MNNrXMpA"
        fingerprint = "v1_sha256_de4807353d2ba977459a1bf7f51fd815e311c0bdc5fccd5e99fd44a766f6866f"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "00bc669f79b2903c5d9e6412050655486111647c646698f9a789e481a7c98662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F8 01 75 56 83 7C 24 3C 10 75 1C BE ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_7f7aba78 {
    meta:
        id = "2o9LlD6TEN8zQLQVEdI5un"
        fingerprint = "v1_sha256_a3b46d29fa51dd6a911cb9cb0e67e9d57d3f3b6697dc8edcc4d82f09d9819a92"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "50b73742726b0b7e00856e288e758412c74371ea2f0eaf75b957d73dfb396fd7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F0 89 D0 31 D8 21 F0 31 D8 03 45 F0 89 CF C1 CF 1B 01 F8 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_ab8ba790 {
    meta:
        id = "3e2g3FMhNWhlR6L6lU7KqX"
        fingerprint = "v1_sha256_2a7a71712ad3f756a2dc53ec80bd9fb625f7c679fd9566945ebfeb392b9874a9"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "2aee0c74d9642ffab1f313179c26400acf60d7cbd2188bade28534d403f468d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { DB F9 66 0F 71 D1 08 66 0F 67 DD 66 0F DB E3 66 0F 71 D3 08 66 0F }
    condition:
        all of them
}

