rule Windows_Trojan_Xpertrat_ce03c41d {
    meta:
        id = "59SF7D6ciI9aCkFrZBLuhV"
        fingerprint = "v1_sha256_f6ff0a11f261bc75c9d0015131f177d39bb9e8e30346a75209ba8fa808ac4fcb"
        version = "1.0"
        date = "2021-08-06"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Xpertrat"
        reference_sample = "d7f2fddb43eb63f9246f0a4535dfcca6da2817592455d7eceaacde666cf1aaae"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[XpertRAT-Mutex]" wide fullword
        $a2 = "XPERTPLUGIN" wide fullword
        $a3 = "keylog.tmp" wide fullword
    condition:
        all of them
}

