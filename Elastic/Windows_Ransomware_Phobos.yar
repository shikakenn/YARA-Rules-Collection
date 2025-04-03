rule Windows_Ransomware_Phobos_a5420148 : beta {
    meta:
        id = "3b9ngzVuWNxgxQHDFJpGGF"
        fingerprint = "v1_sha256_9fcfe41102bee4f8ecf19f30d0bbb2de50e1a1aff4e17c587b5d9adb417527c5"
        version = "1.0"
        date = "2020-06-25"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Phobos ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        threat_name = "Windows.Ransomware.Phobos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 61 00 63 00 75 00 74 00 65 00 00 00 61 00 63 00 74 00 69 00 6E 00 00 00 61 00 63 00 74 00 6F 00 6E 00 00 00 61 00 63 00 74 00 6F 00 72 00 00 00 61 00 63 00 75 00 66 00 66 00 00 }
        $a2 = { 0C 6D 00 73 00 66 00 74 00 65 00 73 00 71 00 6C 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 61 00 67 00 65 00 6E 00 74 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 73 00 65 00 72 00 76 00 72 00 2E 00 65 00 78 00 65 00 00 00 73 00 71 00 6C 00 77 00 72 00 69 00 74 00 65 00 72 00 2E 00 65 00 78 00 65 00 00 00 6F 00 72 00 61 00 63 00 6C 00 65 00 2E 00 65 00 78 00 }
        $a3 = { 31 00 63 00 64 00 00 00 33 00 64 00 73 00 00 00 33 00 66 00 72 00 00 00 33 00 67 00 32 00 00 00 33 00 67 00 70 00 00 00 37 00 7A 00 00 00 61 00 63 00 63 00 64 00 61 00 00 00 61 00 63 00 63 00 64 00 62 00 00 00 61 00 63 00 63 00 64 00 63 00 00 00 61 00 63 00 63 00 64 00 65 00 00 00 61 00 63 00 63 00 64 00 74 00 00 00 61 00 63 00 63 00 64 00 77 00 00 00 61 00 64 00 62 00 00 00 61 00 64 00 70 00 00 00 61 00 69 00 00 00 61 00 69 00 33 00 00 00 61 00 69 00 34 00 00 00 61 00 69 00 35 00 00 00 61 00 69 00 36 00 00 00 61 00 69 00 37 00 00 00 61 00 69 00 38 00 00 00 61 00 6E 00 69 00 6D 00 00 00 61 00 72 00 77 00 00 00 61 00 73 00 00 00 61 00 73 00 61 00 00 00 61 00 73 00 63 00 00 00 61 00 73 00 63 00 78 00 00 00 61 00 73 00 6D 00 00 00 61 00 73 00 6D 00 78 00 00 00 61 00 73 00 70 00 00 00 61 00 73 00 70 00 78 00 00 00 61 00 73 00 72 00 00 00 61 00 73 00 78 00 00 00 61 00 76 00 69 00 00 00 61 00 76 00 73 00 00 00 62 00 61 00 63 00 6B 00 75 00 70 00 00 00 62 00 61 00 6B 00 00 00 62 00 61 00 79 00 00 00 62 00 64 00 00 00 62 00 69 00 6E 00 00 00 62 00 6D 00 70 00 00 00 }
    condition:
        2 of ($a*)
}

rule Windows_Ransomware_Phobos_ff55774d : beta {
    meta:
        id = "2qV3UT98o8PSDl5QkdI2hr"
        fingerprint = "v1_sha256_9ee41b9638a8cc1d9f9b254878c935c531b2f599be59550b3617b1de8cba2ba5"
        version = "1.0"
        date = "2020-06-25"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Phobos ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        threat_name = "Windows.Ransomware.Phobos"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1 = { 24 18 83 C4 0C 8B 4F 0C 03 C6 50 8D 54 24 18 52 51 6A 00 6A 00 89 44 }
    condition:
        1 of ($c*)
}

rule Windows_Ransomware_Phobos_11ea7be5 : beta {
    meta:
        id = "54Jd0OPMygL8hcpAmn0lfA"
        fingerprint = "v1_sha256_1f86695f316200c92d0d02f5f3ba9f68854978f98db5d4291a81c06c9f0b8d28"
        version = "1.0"
        date = "2020-06-25"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Phobos ransomware"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
        threat_name = "Windows.Ransomware.Phobos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b1 = { C0 74 30 33 C0 40 8B CE D3 E0 85 C7 74 19 66 8B 04 73 66 89 }
    condition:
        1 of ($b*)
}

