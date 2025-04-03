rule Linux_Trojan_Bluez_50e87fa9 {
    meta:
        id = "5C5GS1ucbL9R8ZYbvHQYhh"
        fingerprint = "v1_sha256_53754c538a7dea6f06e37980901350feddc3517821ea42544cb96e371709752f"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "1e526b6e3be273489afa8f0a3d50be233b97dc07f85815cc2231a87f5a651ef1"
        threat_name = "Linux.Trojan.Bluez"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 63 68 72 00 6B 69 6C 6C 00 73 74 72 6C 65 6E 00 62 69 6E 64 00 }
    condition:
        all of them
}

