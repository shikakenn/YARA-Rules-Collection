rule Windows_Ransomware_WannaCry_d9855102 {
    meta:
        id = "6EUIMJNFg85BpZXfHEhiwR"
        fingerprint = "v1_sha256_5edf6a42c9f20de3819b46f24be243940b79e7e9004fee3d601794ea0b534cf1"
        version = "1.0"
        date = "2022-08-29"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.WannaCry"
        reference_sample = "0b7878babbaf7c63d808f3ce32c7306cb785fdfb1ceb73be07fb48fdd091fdfb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "@WanaDecryptor@.exe" wide fullword
        $a2 = ".WNCRY" wide fullword
        $a3 = "$%d worth of bitcoin" fullword
        $a4 = "%d%d.bat" fullword
        $a5 = "This folder protects against ransomware. Modifying it will reduce protection" wide fullword
        $b1 = { 53 55 56 57 FF 15 D0 70 00 10 8B E8 A1 8C DD 00 10 85 C0 75 6A 68 B8 0B 00 00 FF 15 70 70 00 10 }
        $b2 = { A1 90 DD 00 10 53 56 57 85 C0 75 3E 8B 1D 60 71 00 10 8B 3D 70 70 00 10 6A 00 FF D3 83 C4 04 A3 }
        $b3 = { 56 8B 74 24 08 57 8B 3D 70 70 00 10 56 E8 2E FF FF FF 83 C4 04 A3 8C DD 00 10 85 C0 75 09 68 88 }
    condition:
        5 of ($a*) or 1 of ($b*)
}

