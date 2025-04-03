rule Windows_Trojan_Jupyter_56152e31 {
    meta:
        id = "6Im2AlEsZKPykeOwZvyKg4"
        fingerprint = "v1_sha256_7b32e9caca744f4f6b48aefa5fda111e6b7ac81a62dd1fb8873d2c800ac3c42b"
        version = "1.0"
        date = "2021-07-22"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Jupyter"
        reference_sample = "ce486097ad2491aba8b1c120f6d0aa23eaf59cf698b57d2113faab696d03c601"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%appdata%\\solarmarker.dat" ascii fullword
        $a2 = "\\AppData\\Roaming\\solarmarker.dat" wide fullword
        $b1 = "steal_passwords" ascii fullword
        $b2 = "jupyter" ascii fullword
    condition:
        1 of ($a*) or 2 of ($b*)
}

