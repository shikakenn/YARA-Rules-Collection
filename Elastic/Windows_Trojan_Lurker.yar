rule Windows_Trojan_Lurker_0ee51802 {
    meta:
        id = "iSYWi1bTVBZ41qBoIIasI"
        fingerprint = "v1_sha256_782926c927dce82b95e51634d5607c474937e1edc0f7f739acefa0f4c03aa753"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Lurker"
        reference_sample = "5718fd4f807e29e48a8b6a6f4484426ba96c61ec8630dc78677686e0c9ba2b87"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\Device\\ZHWLurker0410" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

