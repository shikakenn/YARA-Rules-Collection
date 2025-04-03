rule Windows_Trojan_OnlyLogger_b9e88336 {
    meta:
        id = "6aYN87BpfjXaJtm5LNnlax"
        fingerprint = "v1_sha256_b8d1c4c1e33fc0b54a62f82b8f53c9a1b051ad8c2f578d2a43f504158d1d9247"
        version = "1.0"
        date = "2022-03-22"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.OnlyLogger"
        reference_sample = "69876ee4d89ba68ee86f1a4eaf0a7cb51a012752e14c952a177cd5ffd8190986"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "C:\\Users\\Ddani\\source\\repos\\onlyLogger\\Release\\onlyLogger.pdb" ascii fullword
        $b1 = "iplogger.org" ascii fullword
        $b2 = "NOT elevated" ascii fullword
        $b3 = "WinHttpSendRequest" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_OnlyLogger_ec14d5f2 {
    meta:
        id = "3Ek4xEKntd7em0ypSb2r0m"
        fingerprint = "v1_sha256_2838851a5e013705b64625801d2ab1d56cfc17c52f75a5fd71448cb0a4b4b683"
        version = "1.0"
        date = "2022-03-22"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.OnlyLogger"
        reference_sample = "f45adcc2aad5c0fd900df4521f404bc9ca71b01e3378a5490f5ae2f0c711912e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "KILLME" ascii fullword
        $a2 = "%d-%m-%Y %H" ascii fullword
        $a3 = "/c taskkill /im \"" ascii fullword
        $a4 = "\" /f & erase \"" ascii fullword
        $a5 = "/info.php?pub=" ascii fullword
    condition:
        all of them
}

