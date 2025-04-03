rule Linux_Trojan_Snowlight_f5c83d35 {
    meta:
        id = "6p8QdOZ1JeFD79NyHdYAgx"
        fingerprint = "v1_sha256_fef8f44e897a0f453be2f84d28886d27e261f8256c53c0425c5265b138ce5f40"
        version = "1.0"
        date = "2024-05-16"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.mandiant.com/resources/blog/initial-access-brokers-exploit-f5-screenconnect"
        threat_name = "Linux.Trojan.Snowlight"
        reference_sample = "7d6652d8fa3748d7f58d7e15cefee5a48126d0209cf674818f55e9a68248be01"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 83 EC 08 48 8B 05 A5 07 20 00 48 85 C0 74 05 E8 BB 00 00 00 48 83 C4 08 C3 00 00 00 00 00 00 FF 35 9A 07 20 00 FF 25 9C 07 20 00 0F 1F 40 00 FF 25 9A 07 20 00 68 00 00 00 00 E9 E0 FF FF FF }
    condition:
        all of them
}

