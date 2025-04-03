rule Windows_Trojan_Dridex_63ddf193 {
    meta:
        id = "4Fkh84eB3kUqiSgfdFej0R"
        fingerprint = "v1_sha256_e792f4693be0a7c71d1e638212a8fb3acb1e14dedd48218861fad8c09811da29"
        version = "1.0"
        date = "2021-08-07"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Dridex"
        reference_sample = "b1d66350978808577159acc7dc7faaa273e82c103487a90bf0d040afa000cb0d"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "snxhk.dll" ascii fullword
        $a2 = "LondLibruryA" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Dridex_c6f01353 {
    meta:
        id = "6LcvOa0sm0XU0MwQBspobI"
        fingerprint = "v1_sha256_7146204d779610c04badfc7d884ff882ff5f1439b61f889d1edf4419240c5751"
        version = "1.0"
        date = "2021-08-07"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Dridex"
        reference_sample = "739682ccb54170e435730c54ba9f7e09f32a3473c07d2d18ae669235dcfe84de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 56 57 55 8B FA 85 C9 74 58 85 FF 74 54 0F B7 37 85 F6 75 04 }
    condition:
        all of them
}

