rule Windows_Trojan_Bandook_38497690 {
    meta:
        id = "1Jf5Z30XlDxEyI1P4JQSZf"
        fingerprint = "v1_sha256_199614993f63636764808313f25199348afdf4d537c8dca06f673559e34636b8"
        version = "1.0"
        date = "2022-08-10"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Bandook"
        reference_sample = "4d079586a51168aac708a9ab7d11a5a49dfe7a16d9ced852fbbc5884020c0c97"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "%s~!%s~!%s~!%s~!%s~!%s~!"
        $str2 = "ammyy.abc"
        $str3 = "StealUSB"
        $str4 = "DisableMouseCapture"
        $str5 = "%sSkype\\%s\\config.xml"
        $str6 = "AVE_MARIA"
    condition:
        3 of them
}

