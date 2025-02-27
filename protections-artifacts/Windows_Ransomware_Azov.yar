rule Windows_Ransomware_Azov_e1ef131e {
    meta:
        id = "4IeI6rvk8SK0gHktvyviDF"
        fingerprint = "v1_sha256_8c3a3e73fae6cec093b67a12d91c41c28c7833f3ea5734ea00794ac024898b9e"
        version = "1.0"
        date = "2024-08-21"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Azov"
        reference_sample = "0a80e3b2fef96a8f300cfa92a3fe80e9006ed1e81d2bdc84936ffe7281bfc284"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 83 EC 20 40 80 E4 F0 C6 45 F3 56 C6 45 F4 69 C6 45 F5 72 C6 45 F6 74 C6 45 F7 75 C6 45 F8 61 C6 45 F9 6C C6 45 FA 41 C6 45 FB 6C C6 45 FC 6C C6 45 FD 6F C6 45 FE 63 C6 45 FF 00 }
        $b = "Local\\Kasimir_%c" wide fullword
        $s1 = "\\User Data\\Default\\Cache\\" wide fullword
        $s2 = "\\Low\\Content.IE5\\" wide fullword
        $s3 = "\\cache2\\entries" wide fullword
    condition:
        4 of them
}

