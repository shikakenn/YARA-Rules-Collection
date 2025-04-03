rule Windows_Trojan_Sliver_46525b49 {
    meta:
        id = "7TOwGkDeeMXFChXz0yglnw"
        fingerprint = "v1_sha256_6e61d82b191a740882bcfeac2f2cf337e19ace7b05784ff041b6af2f79ed8809"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Sliver"
        reference_sample = "ecce5071c28940a1098aca3124b3f82e0630c4453f4f32e1b91576aac357ac9c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { B6 54 0C 48 0F B6 74 0C 38 31 D6 40 88 74 0C 38 48 FF C1 48 83 }
        $a2 = { 42 18 4C 8B 4A 20 48 8B 52 28 48 39 D9 73 51 48 89 94 24 C0 00 }
    condition:
        all of them
}

rule Windows_Trojan_Sliver_c9cae357 {
    meta:
        id = "7DjSXTquu7U5L2mLlfWhZ7"
        fingerprint = "v1_sha256_fea862352981787055961b1171de9b69a9c13d246f434809c8f4416d5c49a0ff"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Sliver"
        reference_sample = "27210d8d6e16c492c2ee61a59d39c461312f5563221ad4a0917d4e93b699418e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { B1 F9 3C 0A 68 0F B4 B5 B5 B5 21 B2 38 23 29 D8 6F 83 EC 68 51 8E }
    condition:
        all of them
}

rule Windows_Trojan_Sliver_1dd6d9c2 {
    meta:
        id = "2FQXSOrVSNHd2FLKwZ69Kf"
        fingerprint = "v1_sha256_5ef70322a6ee3dec609d2881b7624d25bc0297a2e6f43ac60834745e6a258cf3"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Sliver"
        reference_sample = "dc508a3e9ea093200acfc1ceebebb2b56686f4764fd8c94ab8c58eec7ee85c8b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { B7 11 49 89 DB C1 EB 10 41 01 DA 66 45 89 11 4C 89 DB EB B6 4D 8D }
        $a2 = { 36 2E 33 20 62 75 69 6C 48 39 }
    condition:
        all of them
}

