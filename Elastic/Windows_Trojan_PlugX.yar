rule Windows_Trojan_PlugX_5f3844ff {
    meta:
        id = "7h153ykW9LJVuEze9PyNmE"
        fingerprint = "v1_sha256_a1a484f4cf00ec0775a3f322bae66ce5f9cc52f08306b38f079445233c49bf52"
        version = "1.0"
        date = "2023-08-28"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.PlugX"
        reference_sample = "a823380e46878dfa8deb3ca0dc394db1db23bb2544e2d6e49c0eceeffb595875"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "EAddr:0x%p"
        $a2 = "Host: [%s:%d]" ascii fullword
        $a3 = "CONNECT %s:%d HTTP/1.1" ascii fullword
        $a4 = "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d:" wide fullword
        $a5 = "\\bug.log" wide fullword
    condition:
        all of them
}

rule Windows_Trojan_PlugX_f338dab5 {
    meta:
        id = "fm5k5vVPyWFbpwK4AxHNJ"
        fingerprint = "v1_sha256_0482305a73bc500aa7c266536cb8286ea796f6b1eaba39547bed22313bbb4457"
        version = "1.0"
        date = "2024-06-05"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.PlugX"
        reference_sample = "8af3fc1f8bd13519d78ee83af43daaa8c5e2c3f184c09f5c41941e0c6f68f0f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 45 08 FF B0 60 03 00 00 E8 A8 0C 00 00 83 C4 24 8D 45 08 89 }
        $a2 = { 2C 5E 5F 5B 5D C3 CC 55 53 57 56 83 EC 10 8B 6C 24 30 8B 44 }
        $a3 = { 89 4D D4 83 60 04 00 3B F3 75 40 E8 53 DA FF FF 8B 40 08 89 }
    condition:
        2 of them
}

rule Windows_Trojan_PlugX_31930182 {
    meta:
        id = "43plh6qPSccMk0oGh7uUix"
        fingerprint = "v1_sha256_13520086a051553bbb9d385df7ea9b7a28228ab1089e6b63ca34d54117e53d99"
        version = "1.0"
        date = "2025-01-27"
        modified = "2025-02-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.PlugX"
        reference_sample = "22bbf2f3e262eaeb6d2621396510f6cd81a1ce77600f7f6cb67340335596c544"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Security WIFI Script" wide fullword
        $a2 = "SS.LOG" wide fullword
        $a3 = "%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X" wide fullword
        $a4 = "ping 127.0.0.1 -n 5 > nul 2 > nul" wide fullword
        $a5 = "cmd.exe /c schtasks.exe /create /sc minute /mo 30 /tn \"" wide fullword
        $a6 = "del *.* /f /s /q /a" wide fullword
        $a7 = "ECode: 0x%p," wide fullword
        $a8 = "########" fullword
        $a9 = "Software\\CLASSES\\ms-pu" wide fullword
    condition:
        6 of them
}

