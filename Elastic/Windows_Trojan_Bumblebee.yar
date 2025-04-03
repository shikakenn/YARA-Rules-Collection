rule Windows_Trojan_Bumblebee_35f50bea {
    meta:
        id = "1tuApCKNFv29UeJHCcg3a7"
        fingerprint = "v1_sha256_9f22b1b7f9e2d7858738d02730ef5477f8d430ad3606ebf4ac8b01314fdc9c46"
        version = "1.0"
        date = "2022-04-28"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bumblebee"
        reference_sample = "9fff05a5aa9cbbf7d37bc302d8411cbd63fb3a28dc6f5163798ae899b9edcda6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 43 28 45 33 D2 4D 8D 0C 00 44 88 54 24 20 66 48 0F 7E C9 66 0F }
        $a2 = { 31 DA 48 31 C7 45 ?? C9 B9 E8 03 C7 45 ?? 00 00 BA 01 C7 45 ?? 00 00 00 48 C7 45 ?? B8 88 77 66 C7 45 ?? 55 44 33 22 C7 45 ?? 11 FF D0 EB C6 45 }
    condition:
        any of them
}

rule Windows_Trojan_Bumblebee_70bed4f3 {
    meta:
        id = "3qbSea2IhaFzp8K0MCqXAo"
        fingerprint = "v1_sha256_3ff97986bfd8df812c4ef94395b3ac7f9ead4d059c398f8984ee217a1bcee4af"
        version = "1.0"
        date = "2022-04-28"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bumblebee"
        reference_sample = "9fff05a5aa9cbbf7d37bc302d8411cbd63fb3a28dc6f5163798ae899b9edcda6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Checking Virtual PC processes %s " wide fullword
        $a2 = "SELECT * FROM Win32_ComputerSystemProduct" ascii fullword
        $a3 = "Injection-Date" ascii fullword
        $a4 = " -Command \"Wait-Process -Id " ascii fullword
        $a5 = "%WINDIR%\\System32\\wscript.exe" wide fullword
        $a6 = "objShell.Run \"rundll32.exe my_application_path"
        $a7 = "Checking reg key HARDWARE\\Description\\System - %s is set to %s" wide fullword
    condition:
        5 of them
}

