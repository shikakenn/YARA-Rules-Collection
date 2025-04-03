rule Windows_Trojan_PowerSeal_d63f5e54 {
    meta:
        id = "5a1ZWFXZQONyMeudaqwX4J"
        fingerprint = "v1_sha256_523dcff68a51ea8fb022066b5f09394e8174d6c157222a08100de30669898057"
        version = "1.0"
        date = "2023-03-16"
        modified = "2023-05-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        threat_name = "Windows.Trojan.PowerSeal"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "PowerSeal.dll" wide fullword
        $a2 = "InvokePs" ascii fullword
        $a3 = "amsiInitFailed" wide fullword
        $a4 = "is64BitOperatingSystem" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_PowerSeal_2e50f393 {
    meta:
        id = "3DUTC3VQ4EXfCzGuu7POoz"
        fingerprint = "v1_sha256_3ca1d4568fea7b2e4e9d30ba03662a2c28ee8623d887a0336e27989b5c98b55f"
        version = "1.0"
        date = "2023-05-10"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        threat_name = "Windows.Trojan.PowerSeal"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[+] Loading PowerSeal"
        $a2 = "[!] Failed to exec PowerSeal"
        $a3 = "AppDomain: unable to get the name!"
    condition:
        2 of them
}

