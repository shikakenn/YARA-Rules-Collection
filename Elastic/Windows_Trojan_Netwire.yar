rule Windows_Trojan_Netwire_6a7df287 {
    meta:
        id = "NNagz2wfwi3Eukn95HP07"
        fingerprint = "v1_sha256_d5f36e2a81cf0a9037267d39266b4c31ca9c07b05fb9772e296aeac2da6051a5"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        threat_name = "Windows.Trojan.Netwire"
        reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 0F B6 74 0C 10 89 CF 29 C7 F7 C6 DF 00 00 00 74 09 41 89 F3 88 5C }
    condition:
        all of them
}

rule Windows_Trojan_Netwire_1b43df38 {
    meta:
        id = "i7DV2FyRMGqsgdnsWYksa"
        fingerprint = "v1_sha256_bb0eb1c1969bc1416e933822843293c5d41bf9bc3d402fa5dbdc3cdf2f4b394a"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        threat_name = "Windows.Trojan.Netwire"
        reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
        $a2 = "\\Login Data"
        $a3 = "SOFTWARE\\NetWire" fullword
    condition:
        2 of them
}

rule Windows_Trojan_Netwire_f85e4abc {
    meta:
        id = "69Jgc1SKV5ORG7ObqiPyy3"
        fingerprint = "v1_sha256_af8fc8fff2e1a0b6c87ac6d24fecf2e1cefe6313ec66da13fddd1be25c1c3d92"
        version = "1.0"
        date = "2022-08-14"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        threat_name = "Windows.Trojan.Netwire"
        reference_sample = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { C9 0F 44 C8 D0 EB 8A 44 24 12 0F B7 C9 75 D1 32 C0 B3 01 8B CE 88 44 }
    condition:
        all of them
}

rule Windows_Trojan_Netwire_f42cb379 {
    meta:
        id = "4Mk3F9QioPC3NPpVbcT6HH"
        fingerprint = "v1_sha256_fc1436596987d3971a464e707ee6fd5689e7d2800df471c125c1e3f748537f5d"
        version = "1.0"
        date = "2022-08-14"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        threat_name = "Windows.Trojan.Netwire"
        reference_sample = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "http://%s%ComSpec" ascii fullword
        $a2 = "%c%.8x%s" ascii fullword
        $a3 = "%6\\6Z65dlNh\\YlS.dfd" ascii fullword
        $a4 = "GET %s HTTP/1.1" ascii fullword
        $a5 = "R-W65: %6:%S" ascii fullword
        $a6 = "PTLLjPq %6:%S -qq9/G.y" ascii fullword
    condition:
        4 of them
}

