rule Windows_Trojan_SnakeKeylogger_af3faa65 {
    meta:
        id = "6tD1ahHXA3SUIEBba8upYW"
        fingerprint = "v1_sha256_54180a642d40b5366f1b400c347c25dc31397d662d6bb8af33c7d2319c97d3fb"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SnakeKeylogger"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "get_encryptedPassword" ascii fullword
        $a2 = "get_encryptedUsername" ascii fullword
        $a3 = "get_timePasswordChanged" ascii fullword
        $a4 = "get_passwordField" ascii fullword
        $a5 = "set_encryptedPassword" ascii fullword
        $a6 = "get_passwords" ascii fullword
        $a7 = "get_logins" ascii fullword
        $a8 = "GetOutlookPasswords" ascii fullword
        $a9 = "StartKeylogger" ascii fullword
        $a10 = "KeyLoggerEventArgs" ascii fullword
        $a11 = "KeyLoggerEventArgsEventHandler" ascii fullword
        $a12 = "GetDataPassword" ascii fullword
        $a13 = "_encryptedPassword" ascii fullword
        $b1 = "----------------S--------N--------A--------K--------E----------------"
        $c1 = "SNAKE-KEYLOGGER" ascii fullword
    condition:
        8 of ($a*) or #b1 > 5 or #c1 > 5
}

