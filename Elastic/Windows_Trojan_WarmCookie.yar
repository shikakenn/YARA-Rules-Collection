rule Windows_Trojan_WarmCookie_7d32fa90 {
    meta:
        id = "75IkxLtavDzNdoJfHwEfIT"
        fingerprint = "v1_sha256_ed3be6e5c6127ef87f9ef6fe35b17815b96706e8e73a393ee9b0a8e3b0cd8f66"
        version = "1.0"
        date = "2024-04-29"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/dipping-into-danger"
        threat_name = "Windows.Trojan.WarmCookie"
        reference_sample = "ccde1ded028948f5cd3277d2d4af6b22fa33f53abde84ea2aa01f1872fad1d13"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $seq_checksum = { 45 8D 5D ?? 45 33 C0 41 83 E3 ?? 49 8D 4E ?? 44 03 DB 41 8D 53 ?? }
        $seq_string_decrypt = { 8B 69 04 48 8D 79 08 8B 31 89 6C 24 ?? 48 8D 4E ?? E8 }
        $seq_filesearch = { 48 81 EC 58 02 00 00 48 8B 05 82 0A 02 00 48 33 C4 48 89 84 24 40 02 00 00 45 33 C9 48 8D 44 24 30 45 33 C0 48 89 44 24 20 33 C9 41 8D 51 1A FF 15 83 4D 01 00 85 C0 78 22 48 8D 4C 24 30 E8 1D }
        $seq_registry = { 48 81 EC 80 02 00 00 48 8B 05 F7 09 02 00 48 33 C4 48 89 84 24 70 02 00 00 4C 89 B4 24 98 02 00 00 48 8D 0D 4D CA 01 00 45 33 F6 41 8B FE E8 02 4F 00 00 48 8B E8 41 B9 08 01 00 00 48 8D 44 24 }
        $plain_str1 = "release.dll" ascii fullword
        $plain_str2 = "\"Main Invoked.\"" ascii fullword
        $plain_str3 = "\"Main Returned.\"" ascii fullword
        $decrypt_str1 = "ERROR: Cannot write file" wide fullword
        $decrypt_str2 = "OK (No output data)" wide fullword
        $decrypt_str3 = "OK (See 'Files' tab)" wide fullword
        $decrypt_str4 = "cmd.exe /c %ls" wide fullword
        $decrypt_str5 = "Cookie:" wide fullword
        $decrypt_str6 = "%ls\\*.*" wide fullword
    condition:
        (3 of ($plain*)) or (2 of ($seq*)) or 4 of ($decrypt*)
}

rule Windows_Trojan_WarmCookie_e8cd480d {
    meta:
        id = "6Tkp4jeKLvpl54Aiu6tpqx"
        fingerprint = "v1_sha256_addbc2e454771592a0ce6e92784ceec3f9c061f2798fe7450ac750cda5734d36"
        version = "1.0"
        date = "2024-09-20"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/dipping-into-danger"
        threat_name = "Windows.Trojan.WarmCookie"
        reference_sample = "f4d2c9470b322af29b9188a3a590cbe85bacb9cc8fcd7c2e94d82271ded3f659"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $seq1 = { 83 F8 0F 7D 14 E8 [4] 83 F8 05 7D 0A E8 }
        $seq2 = { 72 ?? E8 [4] 3D 00 0F 00 00 7? }
        $seq3 = { B9 E8 03 00 00 FF 15 }
        $seq4 = { 41 B9 04 00 00 00 4C 8D ?4 24 }
        $seq5 = { 48 C7 C1 02 00 00 80 FF 15 [4] 85 C0 0F 85 }
    condition:
        4 of them
}

