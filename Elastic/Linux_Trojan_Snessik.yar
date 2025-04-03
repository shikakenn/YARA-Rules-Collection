rule Linux_Trojan_Snessik_d166f98c {
    meta:
        id = "3jti3wezmDHkIyoiMPy0Eq"
        fingerprint = "v1_sha256_44f15a87d48338aafa408d4bcabef844c8864cd95640ad99208b5035e28ccd27"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Snessik"
        reference_sample = "f3ececc2edfff2f92d80ed3a5140af55b6bebf7cae8642a0d46843162eeddddd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D2 74 3B 83 CA FF F0 0F C1 57 10 85 D2 7F 9F 48 8D 74 24 2E 89 44 }
    condition:
        all of them
}

rule Linux_Trojan_Snessik_e435a79c {
    meta:
        id = "6AvC7qeI5T4ALxsgd1xBzh"
        fingerprint = "v1_sha256_4850530a0566844447f56f4e5cb43c5982b1dcb784bb1aef3e377525b8651ed3"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Snessik"
        reference_sample = "e24749b07f824a4839b462ec4e086a4064b29069e7224c24564e2ad7028d5d60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C6 75 38 31 C0 48 8B 5C 24 68 48 8B 6C 24 70 4C 8B 64 24 78 4C 8B AC 24 80 00 }
    condition:
        all of them
}

