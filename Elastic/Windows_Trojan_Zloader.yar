rule Windows_Trojan_Zloader_5dd0a0bf {
    meta:
        id = "2nxZJPpCClKbLdnaiZ3yzu"
        fingerprint = "v1_sha256_1446a4147e1b06fa66907de857011079c55a8e6bf84276eb8518d33468ba1f83"
        version = "1.0"
        date = "2022-03-03"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { B6 08 89 CA 80 C2 F7 80 FA 05 72 F2 80 F9 20 74 ED 03 5D 0C 8D }
    condition:
        all of them
}

rule Windows_Trojan_Zloader_4fe0f7f1 {
    meta:
        id = "6XMHFdMnJhAjB6gGm7clQk"
        fingerprint = "v1_sha256_b20fafc9db08c7668b49e18f45632594c3a69ec65fe865e79379c544fc424f8d"
        version = "1.0"
        date = "2022-03-03"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 08 8B 75 F0 85 DB 8D 7D 94 89 45 E8 0F 45 FB 31 DB 85 F6 0F }
    condition:
        all of them
}

rule Windows_Trojan_Zloader_363c65ed {
    meta:
        id = "1Rj3ncDWHxU17PfYD0DJke"
        fingerprint = "v1_sha256_d3c530f9929db709067a9e1cc59b9cda9dcd8e19352c79ddaf7af6c91b242afd"
        version = "1.0"
        date = "2022-03-03"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 04 8D 4D E4 8D 55 E8 6A 00 6A 00 51 6A 00 6A 00 50 52 57 53 }
    condition:
        all of them
}

rule Windows_Trojan_Zloader_79535191 {
    meta:
        id = "3OJnm8Kab27d9kU9ISjZo4"
        fingerprint = "v1_sha256_c398a8ca46c6fe3e59481a092867be77a94809b1568cea918aa6450374063857"
        version = "1.0"
        date = "2022-03-03"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Zloader"
        reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 28 4B 74 26 8B 46 FC 85 C0 74 F3 8B 4E F4 8B 16 39 C8 0F 47 C1 8B }
    condition:
        all of them
}

