rule Linux_Cryptominer_Roboto_0b6807f8 {
    meta:
        id = "6hQ6TX0mRBZw0UTaUp3nBP"
        fingerprint = "v1_sha256_d945c7a23b9f435851f3c998231da615e220c259051cf213186c28f3279be1dd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Roboto"
        reference_sample = "c2542e399f865b5c490ee66b882f5ff246786b3f004abb7489ec433c11007dda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FB 49 89 CF 4D 0F AF FC 4D 01 DF 4D 89 CB 4C 0F AF D8 4D 01 FB 4D }
    condition:
        all of them
}

rule Linux_Cryptominer_Roboto_1f1cfe9a {
    meta:
        id = "5SqxeVxKY4GV1RkVw0BYMI"
        fingerprint = "v1_sha256_2171284991b0019379c8d271013a35237c37bc2e13d807caed86f8fb9d2ba418"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Roboto"
        reference_sample = "497a6d426ff93d5cd18cea623074fb209d4f407a02ef8f382f089f1ed3f108c5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 20 85 FF 74 0D 39 FE 73 13 83 FE 0F 77 0E 01 F6 EB F3 BF 01 00 }
    condition:
        all of them
}

