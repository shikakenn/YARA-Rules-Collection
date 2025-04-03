rule Linux_Trojan_Godlua_ed8e6228 {
    meta:
        id = "zktYpAgzKK8BefSeFSmDS"
        fingerprint = "v1_sha256_848ef3b198737f080f19c5fa55dfbc31356427398074f9125c65cb532c52ce7a"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Godlua"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C0 18 48 89 45 E8 EB 60 48 8B 85 58 FF FF FF 48 83 C0 20 48 89 }
    condition:
        all of them
}

