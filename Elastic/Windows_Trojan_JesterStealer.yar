rule Windows_Trojan_JesterStealer_b35c6f4b {
    meta:
        id = "6Mgmx99cvI1EIq7dPwRNeb"
        fingerprint = "v1_sha256_acc49348267e963af9ff6ba7afa053d4056d4068b4386a872e33e025790ba759"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.JesterStealer"
        reference_sample = "10c3846867f70dd26c5a54332ed22070c9e5e0e4f52f05fdae12ead801f7933b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[Decrypt Chrome Password] {0}" wide fullword
        $a2 = "Passwords.txt" wide fullword
        $a3 = "9Stealer.Recovery.FTP.FileZilla+<EnumerateCredentials>d__0" ascii fullword
        $a4 = "/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A \"" wide fullword
        $a5 = "citigroup.com" wide fullword
        $a6 = "Password: {1}" wide fullword
        $a7 = "set_steamLogin" ascii fullword
    condition:
        5 of them
}

rule Windows_Trojan_JesterStealer_8f657f58 {
    meta:
        id = "3a5mVm2plCXb2XOH6od5eS"
        fingerprint = "v1_sha256_20a0d8be9c25d50d4dddd455ecb9739f772f57e988855c7fc2df597b2f67585b"
        version = "1.0"
        date = "2022-02-28"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.JesterStealer"
        reference_sample = "10c3846867f70dd26c5a54332ed22070c9e5e0e4f52f05fdae12ead801f7933b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 27 01 00 00 00 96 08 0B 80 79 01 6C 02 A4 27 01 00 00 00 96 08 }
    condition:
        all of them
}

