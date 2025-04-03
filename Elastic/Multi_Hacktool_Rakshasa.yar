rule Multi_Hacktool_Rakshasa_d5d3ef21 {
    meta:
        id = "3tRYL9CLXTM8exWnyLq2CR"
        fingerprint = "v1_sha256_123cbea0ce02012a9b22a4a241d11aa9acbb58b50a1bd9228da7cadbf0fa1b4e"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-01-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        threat_name = "Multi.Hacktool.Rakshasa"
        reference_sample = "ccfa30a40445d5237aaee1e015ecfcd9bdbe7665a6dc2736b28e5ebf07ec4597"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = { 35 B8 00 00 00 48 89 74 24 38 48 89 5C 24 40 48 89 4C 24 48 48 89 54 }
        $a2 = "rakshasa/server.init.4.func2" ascii fullword
        $a3 = "type..eq.rakshasa/server.Conn" ascii fullword
        $a4 = "rakshasa_lite/aes.Str2bytes" ascii fullword
        $a5 = "rakshasa_lite/server.doShellcode" ascii fullword
    condition:
        2 of them
}

