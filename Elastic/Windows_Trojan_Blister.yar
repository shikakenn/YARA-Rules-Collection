rule Windows_Trojan_Blister_cb99a1df {
    meta:
        id = "1rW8WYqs4Mm7jejuMZ9cMs"
        fingerprint = "v1_sha256_deb1be5300d8af12dda868dd5f4ccdbb3ec653bd97c33a09e567c13ecafb9e8a"
        version = "1.0"
        date = "2021-12-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "0a7778cf6f9a1bd894e89f282f2e40f9d6c9cd4b72be97328e681fe32a1b1a00"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 8D 45 DC 89 5D EC 50 6A 04 8D 45 F0 50 8D 45 EC 50 6A FF FF D7 }
        $a2 = { 75 F7 39 4D FC 0F 85 F3 00 00 00 64 A1 30 00 00 00 53 57 89 75 }
        $b1 = { 78 03 C3 8B 48 20 8B 50 1C 03 CB 8B 78 24 03 D3 8B 40 18 03 FB 89 4D F8 89 55 E0 89 45 E4 85 C0 74 3E 8B 09 8B D6 03 CB 8A 01 84 C0 74 17 C1 C2 09 0F BE C0 03 D0 41 8A 01 84 C0 75 F1 81 FA B2 17 EB 41 74 27 8B 4D F8 83 C7 02 8B 45 F4 83 C1 04 40 89 4D F8 89 45 F4 0F B7 C0 3B 45 E4 72 C2 8B FE 8B 45 04 B9 }
    condition:
        any of them
}

rule Windows_Trojan_Blister_9d757838 {
    meta:
        id = "5Dv8RnqWOPM5xeNtgJnSnG"
        fingerprint = "v1_sha256_4d9ce1622d77b2ac8b20b2dfb60ac672752dabab315221a5449ebd3c73a3edca"
        version = "1.0"
        date = "2022-04-26"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "863de84a39c9f741d8103db83b076695d0d10a7384e4e3ba319c05a6018d9737"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 65 48 8B 04 25 60 00 00 00 44 0F B7 DB 48 8B 48 ?? 48 8B 41 ?? C7 45 48 ?? ?? ?? ?? 4C 8B 40 ?? 49 63 40 ?? }
        $a2 = { B9 FF FF FF 7F 89 5D 40 8B C1 44 8D 63 ?? F0 44 01 65 40 49 2B C4 75 ?? 39 4D 40 0F 85 ?? ?? ?? ?? 65 48 8B 04 25 60 00 00 00 44 0F B7 DB }
    condition:
        any of them
}

rule Windows_Trojan_Blister_68b53e1b {
    meta:
        id = "5m0hhJmO3HQ0PsPTp42ZV5"
        fingerprint = "v1_sha256_6d935461406a6b9b39867d52aa5ecb088945ae0f8c56895a67e8565e5a2a3699"
        version = "1.0"
        date = "2023-08-02"
        modified = "2023-08-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "5fc79a4499bafa3a881778ef51ce29ef015ee58a587e3614702e69da304395db"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b_loader_xor = { 48 8B C3 49 03 DC 83 E0 03 8A 44 05 48 [2-3] ?? 03 ?? 4D 2B ?? 75 }
        $b_loader_virtual_protect = { 48 8D 45 50 41 ?? ?? ?? ?? 00 4C 8D ?? 04 4C 89 ?? ?? 41 B9 04 00 00 00 4C 89 ?? F0 4C 8D 45 58 48 89 44 24 20 48 8D 55 F0 }
    condition:
        all of them
}

rule Windows_Trojan_Blister_487b0966 {
    meta:
        id = "2ir37XhU5fFWySR6XtYlUR"
        fingerprint = "v1_sha256_521409d03335205507cc6894e0de3ca627eb966a95a2f8e7b931e552ad78bbb7"
        version = "1.0"
        date = "2023-09-11"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "5fc79a4499bafa3a881778ef51ce29ef015ee58a587e3614702e69da304395db"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b_loader0 = { 65 48 8B 04 25 60 00 00 00 44 8B D3 41 BE ?? ?? ?? ?? 48 8B 50 18 48 83 C2 ?? 48 8B 0A }
        $b_loader1 = { 0F B7 C0 4D 8D 49 02 41 33 C0 44 69 C0 ?? ?? ?? ?? 41 8B C0 C1 E8 0F 44 33 C0 41 0F B7 01 66 85 C0 }
        $b_loader2 = { 66 45 03 DC 49 83 C2 04 41 0F B7 C3 49 83 C0 02 3B C6 }
    condition:
        2 of them
}

rule Windows_Trojan_Blister_26f8c5f2 {
    meta:
        id = "5WBbU91Mx9hQy1P5mA5zBK"
        fingerprint = "v1_sha256_dc87a3ae4edf0b8ee18cb7c34f9b4a0305c504b7ef66cb3232c91dc364d3563c"
        version = "1.0"
        date = "2024-09-25"
        modified = "2024-10-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "cba30fb1731e165acc256d99d32f3c9e5abfa27d152419d24a91d8b79c5c5cb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 41 0F B7 04 40 4D 85 D8 45 3A D4 66 41 89 04 4A 41 84 DE 66 41 39 1C 50 }
        $b = { 41 FF C1 F9 41 0F B7 04 40 4D 85 D8 45 3A D4 66 41 89 04 4A }
    condition:
        any of them
}

