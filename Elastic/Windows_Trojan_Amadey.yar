rule Windows_Trojan_Amadey_7abb059b {
    meta:
        id = "1DZCYuRqfdmxyhuqf2aF9S"
        fingerprint = "v1_sha256_23b75d6df9e2a7f8e1efee46ecaf1fc84247312b19a8a1941ddbca1b2ce5e1db"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Amadey"
        reference_sample = "33e6b58ce9571ca7208d1c98610005acd439f3e37d2329dae8eb871a2c4c297e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }
    condition:
        all of them
}

rule Windows_Trojan_Amadey_c4df8d4a {
    meta:
        id = "7fO8G9bd9OTGtoq2oLSRbv"
        fingerprint = "v1_sha256_7f96c4de585223033fb7e7906be6d6898651ecf30be51ed01abde18ef52c0e1e"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Amadey"
        reference_sample = "9039d31d0bd88d0c15ee9074a84f8d14e13f5447439ba80dd759bf937ed20bf2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" fullword
    condition:
        all of them
}

