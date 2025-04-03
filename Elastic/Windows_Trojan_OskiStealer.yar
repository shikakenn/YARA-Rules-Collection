rule Windows_Trojan_OskiStealer_a158b1e3 {
    meta:
        id = "75FbXzqi3QC5QaQZ4fCuB1"
        fingerprint = "v1_sha256_0ddbe0b234ed60f5a3fc537cdaebf39f639ee24fd66143c9036a9f4786d4c51b"
        version = "1.0"
        date = "2022-03-21"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.OskiStealer"
        reference_sample = "568cd515c9a3bce7ef21520761b02cbfc95d8884d5b2dc38fc352af92356c694"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\"os_crypt\":{\"encrypted_key\":\"" ascii fullword
        $a2 = "%s / %s" ascii fullword
        $a3 = "outlook.txt" ascii fullword
        $a4 = "GLoX6gmCFw==" ascii fullword
        $a5 = "KaoQpEzKSjGm8Q==" ascii fullword
    condition:
        all of them
}

