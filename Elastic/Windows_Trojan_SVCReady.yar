rule Windows_Trojan_SVCReady_af498d39 {
    meta:
        id = "6dTN9Sa97wJQ6hxozx5WYp"
        fingerprint = "v1_sha256_e3520103064cf82cd1747f8889667929d23466c9febfda7e4968a3679db97d71"
        version = "1.0"
        date = "2022-06-12"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SVCReady"
        reference_sample = "08e427c92010a8a282c894cf5a77a874e09c08e283a66f1905c131871cc4d273"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "RunPEDllNative::HookNtCreateUserProcess fail: targetMapping.valid" ascii fullword
        $a2 = "Section Mapping error:Process=0x%x Section [%s] res[0x%x] != va[0x%x] Status:%u" ascii fullword
        $a3 = "%s - %I64d < %I64d > %I64d clicks, %I64d pixels, ready=%i" ascii fullword
        $a4 = "Svc:windowThreadRunner done" ascii fullword
        $a5 = "svc commonMain" ascii fullword
    condition:
        4 of them
}

