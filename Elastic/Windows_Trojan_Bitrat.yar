rule Windows_Trojan_Bitrat_34bd6c83 {
    meta:
        id = "4S5wveKhiDneo1sigMkEOo"
        fingerprint = "v1_sha256_d386fc2a4b6a98638328d1aa05a8d8dbb7a1bbcd72943457b1a5a27b056744ef"
        version = "1.0"
        date = "2021-06-13"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bitrat"
        reference_sample = "37f70ae0e4e671c739d402c00f708761e98b155a1eefbedff1236637c4b7690a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "crd_logins_report" ascii fullword
        $a2 = "drives_get" ascii fullword
        $a3 = "files_get" ascii fullword
        $a4 = "shell_stop" ascii fullword
        $a5 = "hvnc_start_ie" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Bitrat_54916275 {
    meta:
        id = "3n4MllC4OoBNL2viCC3xxO"
        fingerprint = "v1_sha256_4c66f79f4bf6bde49bfb9208e6dc1d3b5d041927565e7302381838b0f32da6f4"
        version = "1.0"
        date = "2022-08-29"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bitrat"
        reference_sample = "d3b2c410b431c006c59f14b33e95c0e44e6221b1118340c745911712296f659f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 6A 10 68 50 73 78 00 E8 5F 4D 02 00 8B 7D 08 85 FF 75 0D FF 15 1C 00 6E 00 50 FF 15 68 03 6E 00 }
    condition:
        all of them
}

