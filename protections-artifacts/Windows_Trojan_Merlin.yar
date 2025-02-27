rule Windows_Trojan_Merlin_e8ecb3be {
    meta:
        id = "5w61bfZMHSLB0KmaBqDK9M"
        fingerprint = "v1_sha256_293158c981463544abd0c38694bfc8635ad1a679bbae115521b65879f145cea6"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Merlin"
        reference_sample = "768c120e63d3960a0842dcc538749955ab7caabaeaf3682f6d1e30666aac65a8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }
    condition:
        all of them
}

