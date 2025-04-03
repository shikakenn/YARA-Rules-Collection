rule Windows_Trojan_Remcos_b296e965 {
    meta:
        id = "6KBc2p7bd3Mu6qQNcAuGZG"
        fingerprint = "v1_sha256_069072abd1182eee50cb9937503d47845e7315d8e3cd6b63576adc8f21820c82"
        version = "1.0"
        date = "2021-06-10"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
        threat_name = "Windows.Trojan.Remcos"
        reference_sample = "0ebeffa44bd1c3603e30688ace84ea638fbcf485ca55ddcfd6fbe90609d4f3ed"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Remcos restarted by watchdog!" ascii fullword
        $a2 = "Mutex_RemWatchdog" ascii fullword
        $a3 = "%02i:%02i:%02i:%03i"
        $a4 = "* Remcos v" ascii fullword
    condition:
        2 of them
}

rule Windows_Trojan_Remcos_7591e9f1 {
    meta:
        id = "6aF8UmQKaXTsWh9hO4UNXG"
        fingerprint = "v1_sha256_96acf1ba7740a8d34d929ed4a4fa446c984c3a8f64a603d428e782b6997e4d20"
        version = "1.0"
        date = "2023-06-23"
        modified = "2023-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set"
        threat_name = "Windows.Trojan.Remcos"
        reference_sample = "4e6e5ecd1cf9c88d536c894d74320c77967fe08c75066098082bf237283842fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "ServRem" ascii fullword
        $a2 = "Screenshots" ascii fullword
        $a3 = "MicRecords" ascii fullword
        $a4 = "remcos.exe" wide nocase fullword
        $a5 = "Remcos" wide fullword
        $a6 = "logs.dat" wide fullword
    condition:
        3 of them
}

