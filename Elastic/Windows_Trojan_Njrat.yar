rule Windows_Trojan_Njrat_30f3c220 {
    meta:
        id = "ozlODzBN4JHXouFkqtsXK"
        fingerprint = "v1_sha256_76347165829415646f943bb984cd17ca138cf238d03f114c498dbcec081d5ae3"
        version = "1.0"
        date = "2021-06-13"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Njrat"
        reference_sample = "741a0f3954499c11f9eddc8df7c31e7c59ca41f1a7005646735b8b1d53438c1b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "get_Registry" ascii fullword
        $a2 = "SEE_MASK_NOZONECHECKS" wide fullword
        $a3 = "Download ERROR" wide fullword
        $a4 = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
        $a5 = "netsh firewall delete allowedprogram \"" wide fullword
        $a6 = "[+] System : " wide fullword
    condition:
        3 of them
}

rule Windows_Trojan_Njrat_eb2698d2 {
    meta:
        id = "6Kjxc9jlrgE9FNBfXh8zEi"
        fingerprint = "v1_sha256_c32a641f2d639f56a8137b3e0d0be3261fba30084eeba9d1205974713413af9f"
        version = "1.0"
        date = "2023-05-04"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Njrat"
        reference_sample = "d537397bc41f0a1cb964fa7be6658add5fe58d929ac91500fc7770c116d49608"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 24 65 66 65 39 65 61 64 63 2D 64 34 61 65 2D 34 62 39 65 2D 62 38 61 62 2D 37 65 34 37 66 38 64 62 36 61 63 39 }
    condition:
        all of them
}

