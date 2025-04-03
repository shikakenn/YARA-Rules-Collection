rule Linux_Trojan_Ngioweb_8bd3002c {
    meta:
        id = "2wbakq40i2UuqOe9g7PFIl"
        fingerprint = "v1_sha256_578fd1c3e6091df9550b3c2caf999d7a0432f037b0cc4b15642531e7fdffd7b7"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 18 67 8A 09 84 C9 74 0D 80 F9 2E 75 02 FF C0 FF 44 24 18 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_a592a280 {
    meta:
        id = "1M790tqsb99PrWcfXuQIuq"
        fingerprint = "v1_sha256_b16cf5b527782680cc1da6f61dd537596792fed615993b19965ef2dbde701e64"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 75 06 8B 7C 24 2C EB 2C 83 FD 01 75 06 8B 7C 24 3C EB 21 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d57aa841 {
    meta:
        id = "7Lb86IBgJDgnaH7yQGwXHM"
        fingerprint = "v1_sha256_b0db72ad81d27f5b2ac2d2bb903ff10849c304d40619fd95a39e7d48c64c45ba"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 0C 48 89 4C 24 10 4C 89 44 24 18 66 83 F8 02 74 10 BB 10 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_b97e0253 {
    meta:
        id = "3CLzMdhxaFbx9dw8xCSfff"
        fingerprint = "v1_sha256_dc11d50166a4d1b400c0df81295054192d42822dd3e065e374a92a31727d4dbd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 5C 41 5D 41 5E 41 5F C3 67 0F BE 17 39 F2 74 12 84 D2 74 04 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_66c465a0 {
    meta:
        id = "7cYooGJOKsa6m76J0Z3XwU"
        fingerprint = "v1_sha256_71f224e3ee1ff29787258a61f29a37a9ddc51e9cb5df0693ea52fd4b6f0b5ad8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 75 E6 B2 07 FE C0 EB DE 83 EC 10 6A 00 6A 00 6A 00 6A 00 FF 74 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d8573802 {
    meta:
        id = "3OK5sVFY0ZI6OaCLTSdrXZ"
        fingerprint = "v1_sha256_b51ab7a7c26e889a4e8efc2b9883f709c17d82032b0c28ab3e30229d6f296367"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 10 40 74 38 51 51 6A 02 FF 74 24 18 FF 93 C8 00 00 00 83 C4 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_7926bc8e {
    meta:
        id = "10uwkFXILhORN7iHOp1TIT"
        fingerprint = "v1_sha256_ac42dd714696825d64402861e96122cce7cd09ae8d9c43a19dd9cf95d7b09610"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { ED 74 31 48 8B 5B 10 4A 8D 6C 3B FC 48 39 EB 77 23 8B 3B 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_e2377400 {
    meta:
        id = "3u3u9qjRBi8RibjN1VTPPr"
        fingerprint = "v1_sha256_71276698d1bdb9bc494fe6f1aa9755940583331836abc490e0b5ac3454d35de6"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "b88daf00a0e890b6750e691856b0fe7428d90d417d9503f62a917053e340228b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EC 08 8B 5C 24 10 8B 43 20 85 C0 74 72 83 7B 28 00 74 6C 83 7B }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_994f1e97 {
    meta:
        id = "2wSlS0nmfeY4IxgUeZxSKD"
        fingerprint = "v1_sha256_2384e787877b622445d7d14053a8340d2e97d3ab103a3fabfa08a40068726ad0"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Ngioweb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C6 44 24 16 68 C6 44 24 15 63 C6 44 24 14 74 C6 44 24 13 61 C6 44 24 12 77 C6 44 24 11 2F C6 44 24 10 76 C6 44 24 0F 65 C6 44 24 0E 64 C6 44 24 0D 2F }
    condition:
        all of them
}

