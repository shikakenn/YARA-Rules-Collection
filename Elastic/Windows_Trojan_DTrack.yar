rule Windows_Trojan_DTrack_57db861f {
    meta:
        id = "48vzc3BEsStUfJ5GNGAxk6"
        fingerprint = "v1_sha256_0ce167ff085ac2d5ccf2ced1193f51843ae937e8bea5cdd7817be26fc46cc542"
        version = "1.0"
        date = "2024-12-27"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DTrack"
        reference_sample = "c8df8511bccc588daf87583ea40836acfddefb5416b860799835ea6f93f9ce5f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str_0 = "%sExecute_%s.log" fullword
        $str_1 = "%02X:%02X:%02X:%02X:%02X:%02X" fullword
        $str_2 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d : " fullword
        $log_0 = "[+] DownloadToFile" fullword
        $log_1 = "[+] DownloadCommand" fullword
        $log_2 = "[+] StartupThread" fullword
        $log_3 = "[+] Connect" fullword
        $log_4 = "[+] CPT.." fullword
        $binary_0 = { 8B 45 ?? C1 E8 08 8B 4D ?? C1 E9 02 33 4D ?? 8B 55 ?? C1 EA 03 33 CA 8B 55 ?? C1 EA 07 33 CA }
    condition:
        (all of ($str_*)) or (all of ($log_*)) or (1 of ($str_*) and $binary_0)
}

