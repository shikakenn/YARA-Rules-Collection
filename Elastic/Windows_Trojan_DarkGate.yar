rule Windows_Trojan_DarkGate_fa1f1338 {
    meta:
        id = "1PNRlH1lex84zH81ot5RPZ"
        fingerprint = "v1_sha256_d5447a57fc57af52c263b84522346a3e94a464a698de8be77eab3b56156164f2"
        version = "1.0"
        date = "2023-12-14"
        modified = "2024-01-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DarkGate"
        reference_sample = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str0 = "DarkGate has recovered from a Critical error"
        $str1 = "Executing DarkGate inside the new desktop..."
        $str2 = "Restart Darkgate "
    condition:
        2 of them
}

rule Windows_Trojan_DarkGate_07ef6f14 {
    meta:
        id = "5ZRjuiTiQWQMIlfbpKxjoc"
        fingerprint = "v1_sha256_2820286b362b107fc7fc3ec8f1a004a7d7926a84318f2943f58239f1f7e8f1f0"
        version = "1.0"
        date = "2023-12-14"
        modified = "2024-02-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DarkGate"
        reference_sample = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $binary0 = { 8B 04 24 0F B6 44 18 FF 33 F8 43 4E }
        $binary1 = { 8B D7 32 54 1D FF F6 D2 88 54 18 FF 43 4E }
    condition:
        all of them
}

