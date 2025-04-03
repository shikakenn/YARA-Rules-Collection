rule Windows_Ransomware_GandCrab_8d0ca31d {
    meta:
        id = "qrNsfB9yDptT8LGwTQYW1"
        fingerprint = "v1_sha256_0ee46c41031a7e7fbdae0b80bd8c53bfd1a0b9d255072971e74470988e492430"
        version = "1.0"
        date = "2024-08-27"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.GandCrab"
        reference_sample = "29eee4f8b088ec1cdac03a04ca834479fce9a0fdf696224c6f19d573f4e2a703"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $ = "%s\\KRAB-DECRYPT.txt" wide fullword
        $ = { 6A 6E 58 6A 74 66 89 44 24 34 8B F2 58 6A 64 89 4C 24 18 59 6A 6C 5A 66 89 44 24 32 6A 2E 58 66 89 44 24 3A 33 C0 66 89 4C 24 34 66 89 4C 24 3C 8D 4C 24 30 66 89 54 24 36 66 89 54 24 38 66 89 54 24 3E 66 89 54 24 40 89 44 24 42 E8 }
        $ = { 6A 2D 58 66 89 45 90 6A 2D 58 66 89 45 92 6A 2D 58 66 89 45 94 6A 42 58 66 89 45 96 6A 45 58 66 89 45 98 6A 47 58 66 89 45 9A 6A 49 58 66 89 45 9C 6A 4E 58 66 89 45 9E 6A 20 58 66 89 45 A0 6A 50 58 66 89 45 A2 6A 43 58 66 89 45 A4 6A 20 58 66 89 45 A6 6A 44 58 66 89 45 A8 6A 41 58 66 89 45 AA 6A 54 58 66 89 45 AC 6A 41 58 66 89 45 AE 6A 2D 58 66 89 45 B0 6A 2D 58 66 89 45 B2 6A 2D 58 66 89 45 B4 33 C0 66 89 45 B6 }
    condition:
        2 of them
}

