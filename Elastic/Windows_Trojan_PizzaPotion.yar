rule Windows_Trojan_PizzaPotion_d334c613 {
    meta:
        id = "1FXsrVBuYQuuCfzGWLrD0E"
        fingerprint = "v1_sha256_de7d395c8a993abf9858858e56ba0ec4acbf0fa1c8bfe4a34ae95be2205967fc"
        version = "1.0"
        date = "2023-09-13"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.PizzaPotion"
        reference_sample = "37bee101cf34a84cba49adb67a555c6ebd3b8ac7c25d50247b0a014c82630003"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%s%sd.sys" ascii fullword
        $a2 = "curl -v -k -F \"file=@" ascii fullword
        $a3 = "; type=image/jpeg\" --referer drive.google.com --cookie"
        $a4 = "%sd.sys -r -inul"
        $a5 = ".xls d:\\*.xlsx d:\\*.ppt d:\\*.pptx d:\\*.pfx" ascii fullword
        $a6 = "-x\"*.exe\" -x\"*.dll\" -x\"*.jpg\" -x\"*.jpeg\""
    condition:
        4 of them
}

