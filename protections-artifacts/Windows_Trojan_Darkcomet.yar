rule Windows_Trojan_Darkcomet_1df27bcc {
    meta:
        id = "69OQlUlVrIEllBL0MDJGz5"
        fingerprint = "v1_sha256_5886e3316839e64f934a0e84d85074e076f3e1e44f86fee35a87eb560bfa2aa7"
        version = "1.0"
        date = "2021-08-16"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Darkcomet"
        reference_sample = "7fbe87545eef49da0df850719536bb30b196f7ad2d5a34ee795c01381ffda569"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "BTRESULTHTTP Flood|Http Flood task finished!|" ascii fullword
        $a2 = "is now open!|" ascii fullword
        $a3 = "ActiveOnlineKeylogger" ascii fullword
        $a4 = "#BOT#RunPrompt" ascii fullword
        $a5 = "GETMONITORS" ascii fullword
    condition:
        all of them
}

