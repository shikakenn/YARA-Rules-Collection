rule Windows_Trojan_DarkVNC_bd803c2e {
    meta:
        id = "3JluPswfyAVDoMwFFXNsZ4"
        fingerprint = "v1_sha256_d9e8a42a424d6a186939682e1cd2ed794c8a3765824188e863b1b2829650e2d5"
        version = "1.0"
        date = "2023-01-23"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DarkVNC"
        reference_sample = "0fcc1b02fdaf211c772bd4fa1abcdeb5338d95911c226a9250200ff7f8e45601"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "BOT-%s(%s)_%S-%S%u%u" wide fullword
        $a2 = "{%08X-%04X-%04X-%04X-%08X%04X}" wide fullword
        $a3 = "monitor_off / monitor_on" ascii fullword
        $a4 = "bot_shell >" ascii fullword
        $a5 = "keyboard and mouse are blocked !" ascii fullword
    condition:
        all of them
}

