rule Windows_Trojan_Squirrelwaffle_88033ff1 {
    meta:
        id = "1YfFNxXPDYuz4gEzLzMg8S"
        fingerprint = "v1_sha256_695d7d411a4de23ba1517a06bda3ce73add37dca1e6fe9046e7c2dcae237389e"
        version = "1.0"
        date = "2021-09-20"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Squirrelwaffle"
        reference_sample = "00d045c89934c776a70318a36655dcdd77e1fedae0d33c98e301723f323f234c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "start /i /min /b start /i /min /b start /i /min /b " ascii fullword
        $a2 = " HTTP/1.1" ascii fullword
        $a3 = "Host:" ascii fullword
        $a4 = "APPDATA" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Squirrelwaffle_d3b685a1 {
    meta:
        id = "1t2jXxUh8RKLqNe1GSdC1E"
        fingerprint = "v1_sha256_7d187aa75fc767f5009f3090852de4894776f4b3f99f189478e7e9fd9c3acbe7"
        version = "1.0"
        date = "2021-09-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Squirrelwaffle"
        reference_sample = "00d045c89934c776a70318a36655dcdd77e1fedae0d33c98e301723f323f234c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 08 85 C0 75 0F 8D 45 94 50 8D 45 D0 6A 20 50 FF D7 83 C4 0C }
    condition:
        all of them
}

