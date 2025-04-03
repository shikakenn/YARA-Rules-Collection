rule Windows_Trojan_SystemBC_5e883723 {
    meta:
        id = "4trY48qEZYwaDD63bGqAMo"
        fingerprint = "v1_sha256_fde2e0b5debd4d26838fb245fdf8e5103ab5aab9feff900cbba00c1950adc61a"
        version = "1.0"
        date = "2022-03-22"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SystemBC"
        reference_sample = "b432805eb6b2b58dd957481aa8a973be58915c26c04630ce395753c6a5196b14"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "GET /tor/rendezvous2/%s HTTP/1.0" ascii fullword
        $a2 = "https://api.ipify.org/" ascii fullword
        $a3 = "KEY-----" ascii fullword
        $a4 = "Host: %s" ascii fullword
        $a5 = "BEGINDATA" ascii fullword
        $a6 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_SystemBC_c1b58c2f {
    meta:
        id = "4zsRElHD1vfsUJ93Nmw53"
        fingerprint = "v1_sha256_16ed14dac0c30500c5e91759b0a1b321f3bd53ae6aab1389a685582eba72c222"
        version = "1.0"
        date = "2024-05-02"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SystemBC"
        reference_sample = "016fc1db90d9d18fe25ed380606346ef12b886e1db0d80fe58c22da23f6d677d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "GET %s HTTP/1.0" ascii fullword
        $a2 = "HOST1:"
        $a3 = "PORT1:"
        $a4 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
        $a5 = "BEGINDATA" ascii fullword
        $a6 = "socks32.dll" ascii fullword
    condition:
        5 of them
}

