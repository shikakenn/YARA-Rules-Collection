rule Windows_Trojan_DoubleBack_d2246a35 {
    meta:
        id = "4ysT0QoV7x7McNm1KQVQyb"
        fingerprint = "v1_sha256_2241d2c6e5b5896fe6f3b02cb1786c39fa620ee503c4585bd75c8763b6d3c06a"
        version = "1.0"
        date = "2022-05-29"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DoubleBack"
        reference_sample = "03d2a0747d06458ccddf65ff5847a511a105e0ad4dcb5134082623af6f705012"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "client.dll" ascii fullword
        $s2 = "=i.ext;" ascii fullword
        $s3 = "## dbg delay" ascii fullword
        $s4 = "ehost"
        $s5 = "msie"
        $s6 = "POST"
        $s7 = "%s(%04Xh:%u/%u)[%s %s]: %s" ascii fullword
        $x64_powershell_msi_check = { 81 3C 39 70 6F 77 65 74 ?? 81 3C 39 6D 73 69 65 41 }
        $x86_powershell_msi_check = { 81 3C 30 70 6F 77 65 74 ?? 81 3C 30 6D 73 69 65 6A 03 5A 0F }
        $x64_salted_hash_func = { 8B 7D ?? 4C 8D 45 ?? 81 C7 ?? ?? ?? ?? 48 8D 4D ?? BA 04 00 00 00 89 7D ?? }
        $x86_salted_hash_func = { 8B 75 ?? 8D 45 ?? 50 6A ?? 81 C6 ?? ?? ?? ?? 8D 4D ?? 5A 89 75 ?? }
        $x64_guid = { 48 83 EC ?? 45 33 C9 41 B8 DD CC BB AA 45 8D 51 ?? }
        $x86_guid = { 55 8B EC 83 EC ?? B8 DD CC BB AA 56 57 6A ?? 8D 75 ?? 5F }
    condition:
        5 of ($s*) or 2 of ($x64_*) or 2 of ($x86_*)
}

