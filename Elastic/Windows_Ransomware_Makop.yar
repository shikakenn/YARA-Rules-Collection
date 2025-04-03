rule Windows_Ransomware_Makop_3ac2c13c {
    meta:
        id = "1QZp3hU5uNTWgtuCvXwfMM"
        fingerprint = "v1_sha256_3fa7c506010a87ac97f415db32c21af091dff26fd912a8f9f5bb5e8d43a8da9e"
        version = "1.0"
        date = "2021-08-05"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Makop"
        reference_sample = "854226fc4f5388d40cd9e7312797dd63739444d69a67e4126ef60817fa6972ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 20 00 75 15 8B 44 24 10 8B 4C 24 08 8B 54 24 0C 89 46 20 89 }
    condition:
        all of them
}

rule Windows_Ransomware_Makop_3e388338 {
    meta:
        id = "1RHoUMNzADSOKchjpK5gbS"
        fingerprint = "v1_sha256_5a6e5fd725f3d042c0c95b42ad00c93965a49aa6bda6ec5383a239f18d74742e"
        version = "1.0"
        date = "2021-08-05"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Makop"
        reference_sample = "854226fc4f5388d40cd9e7312797dd63739444d69a67e4126ef60817fa6972ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "MPR.dll" ascii fullword
        $a2 = "\"%s\" n%u" wide fullword
        $a3 = "\\\\.\\%c:" wide fullword
        $a4 = "%s\\%s\\%s" wide fullword
        $a5 = "%s\\%s" wide fullword
        $a6 = "Start folder" wide fullword
    condition:
        all of them
}

