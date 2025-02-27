rule Windows_Ransomware_Vhd_b6c1dc32 {
    meta:
        id = "7glcvaQWnC7pTlGq4HDzYV"
        fingerprint = "v1_sha256_aa1d0a591299cdc7411a06bad9cfd3c8930c678ba4c52311e2506943372cd15e"
        version = "1.0"
        date = "2024-12-27"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Vhd"
        reference_sample = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $binary_0 = { 57 8D 8D F0 FD FF FF 68 04 01 00 00 51 E8 ?? ?? ?? ?? 83 C4 0C 8D 95 CC FB FF FF 52 8D 85 F0 FD FF FF 68 04 01 00 00 }
        $binary_1 = { 8D 96 24 03 00 00 33 C0 C7 02 00 00 00 00 81 C3 24 03 00 00 8D 7A 04 B9 C8 00 00 00 F3 AB 8B 03 33 C9 89 02 85 C0 }
        $str_0 = "HowToDecrypt.txt" wide fullword
        $str_1 = "AEEAEE SET" wide fullword
    condition:
        (all of ($str_*)) or (1 of ($str_*) and 1 of ($binary_*))
}

